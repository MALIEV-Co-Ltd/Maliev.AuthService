#!/usr/bin/env bash
set -euo pipefail

readonly messaging_source="${1:-.ci-sources/Maliev.MessagingContracts}"
readonly aspire_source="${2:-.ci-sources/Maliev.Aspire}"
readonly output_path="${3:-.ci-packages}"
readonly messaging_commit="9c41d6524a485bf03ba022b8170f47366ab1a77a"
readonly aspire_commit="979e1bcb3c3ed9c414f652c94b56297543c031b2"
readonly ci_package_version="1.0.0-auth-ci"
readonly ci_nuget_config="$(pwd)/nuget.validation.config"

assert_checkout() {
  local repository_path="$1"
  local expected_commit="$2"
  local actual_commit

  actual_commit="$(git -C "$repository_path" rev-parse HEAD)"
  if [[ "$actual_commit" != "$expected_commit" ]]; then
    printf 'Expected %s at %s, found %s\n' "$repository_path" "$expected_commit" "$actual_commit" >&2
    exit 1
  fi
}

assert_checkout "$messaging_source" "$messaging_commit"
assert_checkout "$aspire_source" "$aspire_commit"

mkdir -p -- "$output_path"
find "$output_path" -maxdepth 1 -type f \( -name '*.nupkg' -o -name '*.snupkg' -o -name 'SHA256SUMS' \) -delete
readonly output_dir="$(cd "$output_path" && pwd)"

readonly messaging_project="$messaging_source/generated/csharp/Maliev.MessagingContracts.csproj"
readonly service_defaults_project="$aspire_source/Maliev.Aspire.ServiceDefaults/Maliev.Aspire.ServiceDefaults.csproj"

dotnet restore "$messaging_project" --configfile "$ci_nuget_config"
dotnet pack "$messaging_project" \
  --configuration Release \
  --no-restore \
  -p:NoWarn=CS1570 \
  -p:PackageVersion="$ci_package_version" \
  --output "$output_dir"

dotnet restore "$service_defaults_project" \
  --configfile "$ci_nuget_config" \
  -p:GITHUB_ACTIONS=true \
  -p:UsePackageReferences=true \
  -p:SharedLibraryVersion="$ci_package_version"
dotnet pack "$service_defaults_project" \
  --configuration Release \
  --no-restore \
  -p:GITHUB_ACTIONS=true \
  -p:UsePackageReferences=true \
  -p:SharedLibraryVersion="$ci_package_version" \
  -p:PackageVersion="$ci_package_version" \
  --output "$output_dir"

test -s "$output_dir/Maliev.MessagingContracts.$ci_package_version.nupkg"
test -s "$output_dir/Maliev.Aspire.ServiceDefaults.$ci_package_version.nupkg"

(
  cd "$output_dir"
  sha256sum \
    "Maliev.MessagingContracts.$ci_package_version.nupkg" \
    "Maliev.Aspire.ServiceDefaults.$ci_package_version.nupkg" \
    > SHA256SUMS
  sha256sum --check SHA256SUMS
)
