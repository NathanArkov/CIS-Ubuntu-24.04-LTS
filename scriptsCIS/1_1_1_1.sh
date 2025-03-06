#!/usr/bin/env bash
{
a_output=() a_output2=() a_output3=() l_dl="" l_mod_name="cramfs"
l_mod_type="fs"
l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
f_module_chk()
{
l_dl="y" a_showconfig=()
while IFS= read -r l_showconfig; do
a_showconfig+=("$l_showconfig")
done < <(modprobe --showconfig | grep -P --
'\b(install|blacklist)\h+'"${l_mod_chk_name//-/_}"'\b')
if ! lsmod | grep "$l_mod_chk_name" &> /dev/null; then
a_output+=(" - kernel module: \"$l_mod_name\" is not loaded")
else
a_output2+=(" - kernel module: \"$l_mod_name\" is loaded")
fi
if grep -Pq -- '\binstall\h+'"${l_mod_chk_name//-
/_}"'\h+(\/usr)?\/bin\/(true|false)\b' <<< "${a_showconfig[*]}"; then
a_output+=(" - kernel module: \"$l_mod_name\" is not loadable")
else
a_output2+=(" - kernel module: \"$l_mod_name\" is loadable")
fi
if grep -Pq -- '\bblacklist\h+'"${l_mod_chk_name//-/_}"'\b' <<<
"${a_showconfig[*]}"; then
a_output+=(" - kernel module: \"$l_mod_name\" is deny listed")
else
a_output2+=(" - kernel module: \"$l_mod_name\" is not deny listed")
fi
}
for l_mod_base_directory in $l_mod_path; do
if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A
"$l_mod_base_directory/${l_mod_name/-/\/}")" ]; then
a_output3+=(" - \"$l_mod_base_directory\"")
l_mod_chk_name="$l_mod_name"
[[ "$l_mod_name" =~ overlay ]] && l_mod_chk_name="${l_mod_name::-2}"
[ "$l_dl" != "y" ] && f_module_chk
else
a_output+=(" - kernel module: \"$l_mod_name\" doesn't exist in
\"$l_mod_base_directory\"")
fi
done
[ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' "" " -- INFO --" " - module:
\"$l_mod_name\" exists in:" "${a_output3[@]}"
if [ "${#a_output2[@]}" -le 0 ]; then
printf '%s\n' "" "- Audit Result:" " ** PASS **" "${a_output[@]}"
else
printf '%s\n' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for
audit failure:" "${a_output2[@]}"
[ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "- Correctly set:"
"${a_output[@]}"
fi
}
