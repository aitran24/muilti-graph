#!/usr/bin/env bash
set -euo pipefail

REPO_CANDIDATES=(
  "${ATTACK_DATA_DIR:-}"
  "/mnt/d/ki8/nckh/data/attack_data"
  "/mnt/d/ki8/nckh/new_pineline/auditlog/attack_data"
  "/d/ki8/nckh/data/attack_data"
  "/d/ki8/nckh/new_pineline/auditlog/attack_data"
)

TECHNIQUES=(
  "T1021.004"
  "T1021.006"
  "T1027"
  "T1033"
  "T1036"
  "T1036.003"
  "T1037.001"
  "T1047"
  "T1048.003"
  "T1049"
  "T1053.002"
  "T1053.003"
  "T1053.005"
  "T1053.006"
  "T1055"
  "T1055.001"
  "T1057"
  "T1059"
  "T1059.001"
  "T1059.003"
  "T1059.004"
  "T1059.005"
  "T1068"
  "T1069.001"
  "T1069.002"
  "T1070"
  "T1070.001"
  "T1070.005"
  "T1071.004"
  "T1078"
  "T1078.002"
  "T1082"
  "T1087.001"
  "T1087.002"
  "T1090.001"
  "T1090.003"
  "T1098"
  "T1098.004"
  "T1105"
  "T1110.001"
)

BASE_PATH="datasets/attack_techniques"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
  printf "${BLUE}[*] %s${NC}\n" "$1"
}

log_ok() {
  printf "${GREEN}[+] %s${NC}\n" "$1"
}

log_warn() {
  printf "${YELLOW}[~] %s${NC}\n" "$1"
}

log_err() {
  printf "${RED}[!] %s${NC}\n" "$1"
}

find_attack_data_repo() {
  local candidate
  for candidate in "${REPO_CANDIDATES[@]}"; do
    [[ -n "${candidate}" ]] || continue
    if [[ -d "${candidate}/.git" && -d "${candidate}/${BASE_PATH}" ]]; then
      printf "%s\n" "${candidate}"
      return 0
    fi
  done
  return 1
}

is_lfs_pointer() {
  local file_path="$1"
  local first_line
  first_line="$(head -n 1 "${file_path}" 2>/dev/null || true)"
  [[ "${first_line}" == "version https://git-lfs.github.com/spec/v1" ]]
}

has_real_log() {
  local tech_dir="$1"
  local file
  while IFS= read -r -d '' file; do
    if ! is_lfs_pointer "${file}"; then
      return 0
    fi
  done < <(find "${tech_dir}" -type f \( -name "*.log" -o -name "*.txt" -o -name "*.xml" \) -print0 2>/dev/null)
  return 1
}

has_lfs_pointer_log() {
  local tech_dir="$1"
  local file
  while IFS= read -r -d '' file; do
    if is_lfs_pointer "${file}"; then
      return 0
    fi
  done < <(find "${tech_dir}" -type f \( -name "*.log" -o -name "*.txt" -o -name "*.xml" \) -print0 2>/dev/null)
  return 1
}

count_logs() {
  local tech_dir="$1"
  find "${tech_dir}" -type f \( -name "*.log" -o -name "*.txt" -o -name "*.xml" \) 2>/dev/null | wc -l | tr -d ' '
}

main() {
  local repo_root
  repo_root="$(find_attack_data_repo)" || {
    log_err "Không tìm thấy repo attack_data. Set ATTACK_DATA_DIR hoặc đặt repo ở /mnt/d/ki8/nckh/data/attack_data"
    exit 1
  }

  if ! command -v git >/dev/null 2>&1; then
    log_err "Thiếu git"
    exit 1
  fi

  if ! command -v git-lfs >/dev/null 2>&1 && ! git lfs version >/dev/null 2>&1; then
    log_err "Thiếu git-lfs"
    exit 1
  fi

  log_info "Dùng repo: ${repo_root}"
  cd "${repo_root}"

  local total="${#TECHNIQUES[@]}"
  local idx=0
  local pulled=0
  local already_complete=0
  local missing_dir=0
  local failed=0

  local -a pulled_list=()
  local -a already_complete_list=()
  local -a missing_dir_list=()
  local -a failed_list=()

  for tech in "${TECHNIQUES[@]}"; do
    idx=$((idx + 1))
    local tech_path="${BASE_PATH}/${tech}"
    printf "${YELLOW}[%2d/%2d] %-10s${NC} " "${idx}" "${total}" "${tech}"

    if [[ ! -d "${tech_path}" ]]; then
      printf "${RED}missing_dir${NC}\n"
      missing_dir=$((missing_dir + 1))
      missing_dir_list+=("${tech}")
      continue
    fi

    if ! has_lfs_pointer_log "${tech_path}"; then
      printf "${GREEN}already_complete${NC}\n"
      already_complete=$((already_complete + 1))
      already_complete_list+=("${tech}")
      continue
    fi

    local log_count
    log_count="$(count_logs "${tech_path}")"
    if [[ "${log_count}" == "0" ]]; then
      printf "${RED}no_log_files${NC}\n"
      failed=$((failed + 1))
      failed_list+=("${tech}")
      continue
    fi

    if git lfs pull --include="${tech_path}/"; then
      if ! has_lfs_pointer_log "${tech_path}" && has_real_log "${tech_path}"; then
        printf "${GREEN}pulled${NC}\n"
        pulled=$((pulled + 1))
        pulled_list+=("${tech}")
      else
        printf "${RED}still_has_pointer_files${NC}\n"
        failed=$((failed + 1))
        failed_list+=("${tech}")
      fi
    else
      printf "${RED}pull_failed${NC}\n"
      failed=$((failed + 1))
      failed_list+=("${tech}")
    fi
  done

  echo
  log_info "Tóm tắt"
  log_ok "Pulled: ${pulled}"
  log_ok "Đã đầy đủ từ trước: ${already_complete}"
  log_warn "Thiếu thư mục technique: ${missing_dir}"
  log_err "Lỗi / vẫn chỉ pointer: ${failed}"

  if [[ ${#already_complete_list[@]} -gt 0 ]]; then
    printf "\n${BLUE}Đã đầy đủ từ trước:${NC}\n"
    printf '  - %s\n' "${already_complete_list[@]}"
  fi

  if [[ ${#pulled_list[@]} -gt 0 ]]; then
    printf "\n${BLUE}Vừa pull xong:${NC}\n"
    printf '  - %s\n' "${pulled_list[@]}"
  fi

  if [[ ${#missing_dir_list[@]} -gt 0 ]]; then
    printf "\n${YELLOW}Thiếu thư mục:${NC}\n"
    printf '  - %s\n' "${missing_dir_list[@]}"
  fi

  if [[ ${#failed_list[@]} -gt 0 ]]; then
    printf "\n${RED}Cần kiểm tra thêm:${NC}\n"
    printf '  - %s\n' "${failed_list[@]}"
  fi
}

main "$@"
