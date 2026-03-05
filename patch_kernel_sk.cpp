#include "patch_kernel_sk.h"
#include "analyze/base_func.h"
#include "analyze/symbol_analyze.h"
#include "patch_do_execve.h"
#include "patch_current_avc_check.h"
#include "patch_avc_denied.h"
#include "patch_audit_log_start.h"
#include "patch_filldir64.h"

#include "3rdparty/find_mrs_register.h"
#include "3rdparty/find_imm_register_offset.h"

struct PatchKernelResult {
	bool patched = false;
	size_t root_key_start = 0;
};

bool check_file_path(const char* file_path) {
	return std::filesystem::path(file_path).extension() != ".img";
}

bool parser_cred_offset(const std::vector<char>& file_buf, const SymbolRegion &symbol, std::string& mode_name, size_t& cred_offset) {
	using namespace a64_find_mrs_register;
	return find_current_task_next_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, mode_name, cred_offset);
}

bool parse_cred_uid_offset(const std::vector<char>& file_buf, const SymbolRegion& symbol, size_t cred_offset, size_t& cred_uid_offset) {
	using namespace a64_find_imm_register_offset;
	cred_uid_offset = 0;
	KernelVersionParser kernel_ver(file_buf);
	size_t min_off = 8;
	if (kernel_ver.is_kernel_version_less("6.6.8")) min_off = 4;

	std::vector<int64_t> candidate_offsets;
	if (!find_imm_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, candidate_offsets))
		return false;

	auto it = std::find(candidate_offsets.begin(), candidate_offsets.end(), cred_offset);
	if (it != candidate_offsets.end()) {
		for (++it; it != candidate_offsets.end(); ++it) {
			if (*it > 0x30 || *it < (int64_t)min_off) continue;
			cred_uid_offset = *it;
			break;
		}
	}
	return cred_uid_offset != 0;
}

bool parser_seccomp_offset(const std::vector<char>& file_buf, const SymbolRegion& symbol, std::string& mode_name, size_t& seccomp_offset) {
	using namespace a64_find_mrs_register;
	return find_current_task_next_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, mode_name, seccomp_offset);
}

void cfi_bypass(const std::vector<char>& file_buf, KernelSymbolOffset &sym, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	if (sym.__cfi_check.offset) {
		PATCH_AND_CONSUME(sym.__cfi_check, patch_ret_cmd(file_buf, sym.__cfi_check.offset, vec_patch_bytes_data));
	}
	if (sym.__cfi_check_fail) {
		patch_ret_cmd(file_buf, sym.__cfi_check_fail, vec_patch_bytes_data);
	}
	if (sym.__cfi_slowpath_diag) {
		patch_ret_cmd(file_buf, sym.__cfi_slowpath_diag, vec_patch_bytes_data);
	}
	if (sym.__cfi_slowpath) {
		patch_ret_cmd(file_buf, sym.__cfi_slowpath, vec_patch_bytes_data);
	}
	if (sym.__ubsan_handle_cfi_check_fail_abort) {
		patch_ret_cmd(file_buf, sym.__ubsan_handle_cfi_check_fail_abort, vec_patch_bytes_data);
	}
	if (sym.__ubsan_handle_cfi_check_fail) {
		patch_ret_cmd(file_buf, sym.__ubsan_handle_cfi_check_fail, vec_patch_bytes_data);
	}
	if (sym.report_cfi_failure) {
		patch_ret_1_cmd(file_buf, sym.report_cfi_failure, vec_patch_bytes_data);
	}
}

PatchKernelResult patch_kernel_handler(const std::vector<char>& file_buf, size_t cred_offset, size_t cred_uid_offset, size_t seccomp_offset, KernelSymbolOffset& sym, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	PatchBase patchBase(file_buf, cred_uid_offset);
	PatchDoExecve patchDoExecve(patchBase, sym);
	PatchCurrentAvcCheck patchCurrentAvcCheck(patchBase);
	PatchAvcDenied patchAvcDenied(patchBase, sym.avc_denied);
	PatchAuditLogStart patchAuditLogStart(patchBase, sym.audit_log_start);
	PatchFilldir64 patchFilldir64(patchBase, sym.filldir64);

	PatchKernelResult r;
	if (!sym.die.offset || !sym.arm64_notify_die.offset || !sym.__drm_printfn_coredump.offset) {
		std::cout << "die/arm64_notify_die/__drm_printfn_coredump 符号区域不可用" << std::endl;
		r.patched = false;
		return r;
	}

	// Pro: die 区域头部预留 4 字节 init_flag（初始值 0）
	char init_flag_buf[4] = { 0 };
	patch_data(file_buf, sym.die.offset, init_flag_buf, sizeof(init_flag_buf), vec_patch_bytes_data);
	sym.die.consume(4);

	r.root_key_start = sym.die.offset;
	PATCH_AND_CONSUME(sym.die, patchDoExecve.patch_do_execve(sym.die, cred_offset, seccomp_offset, vec_patch_bytes_data));
	PATCH_AND_CONSUME(sym.die, patchFilldir64.patch_filldir64_root_key_guide(r.root_key_start, sym.die, vec_patch_bytes_data));
	PATCH_AND_CONSUME(sym.die, patchFilldir64.patch_jump(sym.die.offset, sym.arm64_notify_die.offset, vec_patch_bytes_data));
	PATCH_AND_CONSUME(sym.arm64_notify_die, patchFilldir64.patch_filldir64_core(sym.arm64_notify_die, vec_patch_bytes_data));

	auto current_avc_check_bl_func = sym.__drm_printfn_coredump.offset;
	PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchCurrentAvcCheck.patch_current_avc_check_bl_func(sym.__drm_printfn_coredump, cred_offset, vec_patch_bytes_data));
	PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchAvcDenied.patch_avc_denied(sym.__drm_printfn_coredump, current_avc_check_bl_func, vec_patch_bytes_data));
	PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchAuditLogStart.patch_audit_log_start(sym.__drm_printfn_coredump, current_avc_check_bl_func, vec_patch_bytes_data));

	r.patched = true;
	return r;
}

void write_all_patch(const char* file_path, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	for (auto& item : vec_patch_bytes_data) {
		std::shared_ptr<char> spData(new (std::nothrow) char[item.str_bytes.length() / 2], std::default_delete<char[]>());
		hex2bytes((uint8_t*)item.str_bytes.c_str(), (uint8_t*)spData.get());
		if (!write_file_bytes(file_path, item.write_addr, spData.get(), item.str_bytes.length() / 2)) {
			std::cout << "写入文件发生错误" << std::endl;
		}
	}
	if (vec_patch_bytes_data.size()) {
		std::cout << "Done." << std::endl;
	}
}

int main(int argc, char* argv[]) {
	++argv;
	--argc;

	std::cout << "SKRoot(Pro) ARM64 Linux内核ROOT提权工具 V1.0" << std::endl;
	std::cout << "仅支持 Linux 内核 6.1.x、6.6.x 和 6.12.x" << std::endl << std::endl;

	if (argc < 1) {
		std::cout << "用法: patch_kernel_sk <kernel_binary_file>" << std::endl;
		std::cout << "请输入正确的 Linux 内核二进制文件路径。" << std::endl;
		std::cout << "如果是 boot.img，需要先解压并提取其中的 kernel 文件。" << std::endl;
		return 0;
	}

	const char* file_path = argv[0];
	std::cout << file_path << std::endl << std::endl;
	if (!check_file_path(file_path)) {
		std::cout << "请输入正确的 Linux 内核二进制文件路径。" << std::endl;
		std::cout << "如果是 boot.img，需要先解压并提取其中的 kernel 文件。" << std::endl;
		return 0;
	}

	std::vector<char> file_buf = read_file_buf(file_path);
	if (!file_buf.size()) {
		std::cout << "无法打开文件: " << file_path << std::endl;
		return 0;
	}

	// 版本验证：仅支持 6.1.x 和 6.6.x
	KernelVersionParser kernel_ver(file_buf);
	std::string ver_str = kernel_ver.get_kernel_version();
	if (ver_str.empty()) {
		std::cout << "无法解析内核版本（未找到 'Linux version' 字符串）" << std::endl;
		return 0;
	}
	std::cout << "内核版本: " << ver_str << std::endl;

	int major = 0, minor = 0, patch = 0;
	if (sscanf(ver_str.c_str(), "%d.%d.%d", &major, &minor, &patch) < 2) {
		std::cout << "内核版本解析失败" << std::endl;
		return 0;
	}
	if (major != 6 || (minor != 1 && minor != 6 && minor != 12)) {
		std::cout << "不支持的内核版本: " << ver_str << std::endl;
		std::cout << "本工具仅支持 Linux 内核 6.1.x、6.6.x 和 6.12.x" << std::endl;
		return 0;
	}

	SymbolAnalyze symbol_analyze(file_buf);
	if (!symbol_analyze.analyze_kernel_symbol()) {
		std::cout << "内核符号分析失败" << std::endl;
		return 0;
	}
	KernelSymbolOffset sym = symbol_analyze.get_symbol_offset();

	std::string t_mode_name;
	size_t cred_offset = 0;
	size_t cred_uid_offset = 0;
	size_t seccomp_offset = 0;

	if (!parser_cred_offset(file_buf, sym.sys_getuid, t_mode_name, cred_offset)) {
		std::cout << "cred 偏移解析失败" << std::endl;
		return 0;
	}

	if (!parse_cred_uid_offset(file_buf, sym.sys_getuid, cred_offset, cred_uid_offset)) {
		std::cout << "cred uid 偏移解析失败" << std::endl;
		return 0;
	}

	if (!parser_seccomp_offset(file_buf, sym.prctl_get_seccomp, t_mode_name, seccomp_offset)) {
		std::cout << "seccomp 偏移解析失败" << std::endl;
		return 0;
	}
	std::cout << "结构体偏移解析完成" << std::endl;

	std::vector<patch_bytes_data> vec_patch_bytes_data;
	cfi_bypass(file_buf, sym, vec_patch_bytes_data);

	PatchKernelResult pr = patch_kernel_handler(file_buf, cred_offset, cred_uid_offset, seccomp_offset, sym, vec_patch_bytes_data);
	if (!pr.patched) {
		std::cout << "修补失败：无法找到可用的 hook 区域" << std::endl;
		return 0;
	}

	std::string str_root_key;
	size_t is_need_create_root_key = 0;
	std::cout << std::endl << "请选择是否需要自动随机生成ROOT密匙（1需要；2不需要）：" << std::endl;
	std::cin >> std::dec >> is_need_create_root_key;
	if (is_need_create_root_key == 1) {
		str_root_key = generate_random_str(ROOT_KEY_LEN);
	} else {
		std::cout << "请输入ROOT密匙（48个字符的字符串，包含大小写和数字）：" << std::endl;
		std::cin >> str_root_key;
		std::cout << std::endl;
	}
	std::string write_key = str_root_key;
	write_key.erase(write_key.size() - 1);
	// XOR 混淆：内核中不存储明文 root_key
	for (auto& c : write_key) c ^= ROOT_KEY_XOR_BYTE;
	// null terminator 也需要 XOR（shellcode 用解密后的值判断终止）
	char xor_null = static_cast<char>(ROOT_KEY_XOR_BYTE);
	write_key += xor_null;
	patch_data(file_buf, pr.root_key_start, (void*)write_key.c_str(), write_key.length(), vec_patch_bytes_data);

	std::cout << "#获取ROOT权限的密匙(Key): " << str_root_key.c_str() << std::endl << std::endl;

	size_t need_write_modify_in_file = 0;
	std::cout << "#是否需要立即写入修改到文件？（1需要；2不需要）：" << std::endl;
	std::cin >> need_write_modify_in_file;
	if (need_write_modify_in_file == 1) {
		write_all_patch(file_path, vec_patch_bytes_data);
	}
	return 0;
}
