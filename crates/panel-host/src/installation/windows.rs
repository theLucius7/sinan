use super::{Sha1, Sha256};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::Digest;
use sinan_protocol::release::RELEASE_SOURCE_REPO;

const BOOTSTRAP: &[u8] = include_bytes!("../../../../deploy/bootstrap.ps1");

pub fn bootstrap_url() -> String {
    let mut hash = Sha1::new();
    hash.update(format!("blob {}\0", BOOTSTRAP.len()));
    hash.update(BOOTSTRAP);
    format!(
        "https://api.github.com/repos/{RELEASE_SOURCE_REPO}/git/blobs/{:x}",
        hash.finalize()
    )
}

fn quote(value: &str) -> String {
    // PowerShell treats smart single quotes as delimiters too, at both payload levels.
    let mut literal = String::from("'");
    for character in value.chars() {
        if matches!(
            character,
            '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}'
        ) {
            literal.push(character);
        }
        literal.push(character);
    }
    literal.push('\'');
    literal
}

fn encoded(value: &str) -> String {
    STANDARD.encode(
        value
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
pub fn command(version: &str, panel: &str, token: &str, target: &str) -> String {
    command_with_mirror(version, panel, token, target, "")
}

pub fn command_with_mirror(
    version: &str,
    panel: &str,
    token: &str,
    target: &str,
    mirror: &str,
) -> String {
    let checksum = format!("{:x}", Sha256::digest(BOOTSTRAP));
    let program = format!(
        concat!(
            "$ErrorActionPreference='Stop'; ",
            "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; ",
            "$parent=[Environment]::GetFolderPath('Windows'); ",
            "if((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint){{throw '安装目录禁止重解析点'}}; ",
            "$trusted=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'); ",
            "$current=$parent; while($current){{ ",
            "if((Get-Item -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint){{throw '安装目录祖先禁止重解析点'}}; ",
            "$existing=Get-Acl -LiteralPath $current; ",
            "if($existing.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){{throw '安装目录所有者不可信'}}; ",
            "$mask=[Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles,Delete,ChangePermissions,TakeOwnership'; ",
            "if($current -eq $parent){{$mask=$mask -bor [Security.AccessControl.FileSystemRights]::Write}}; ",
            "foreach($entry in $existing.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){{ ",
            "if($entry.AccessControlType -eq 'Allow' -and ($entry.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and ($entry.FileSystemRights -band $mask) -ne 0 -and $entry.IdentityReference.Value -notin $trusted){{throw '安装目录允许非管理员替换或写入'}} }}; ",
            "$up=[IO.Directory]::GetParent($current); $current=if($up){{$up.FullName}}else{{$null}} }}; ",
            "$d=Join-Path $parent ('sinan-install-'+[Guid]::NewGuid().ToString('N')); ",
            "$acl=[Security.AccessControl.DirectorySecurity]::new(); ",
            "$acl.SetAccessRuleProtection($true,$false); ",
            "$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')); ",
            "foreach($sid in @('S-1-5-18','S-1-5-32-544')){{ ",
            "$rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), ",
            "[Security.AccessControl.FileSystemRights]::FullControl, ",
            "[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit', ",
            "[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow); $acl.AddAccessRule($rule)}}; ",
            "[void][IO.Directory]::CreateDirectory($d); Set-Acl -LiteralPath $d -AclObject $acl; ",
            "try{{ ",
            "Add-Type -AssemblyName System.Net.Http; $h=[Net.Http.HttpClientHandler]::new(); ",
            "$h.UseProxy=$false; $h.AllowAutoRedirect=$false; ",
            "$c=[Net.Http.HttpClient]::new($h); $c.Timeout=[TimeSpan]::FromSeconds(120); ",
            "$c.MaxResponseContentBufferSize=262144; $c.DefaultRequestHeaders.UserAgent.ParseAdd('sinan-bootstrap'); ",
            "$c.DefaultRequestHeaders.Accept.ParseAdd('application/vnd.github.raw+json'); ",
            "try{{$r=$c.GetAsync({url}).GetAwaiter().GetResult(); ",
            "try{{if([int]$r.StatusCode -ne 200){{throw '可信安装器下载失败'}}; ",
            "$bytes=$r.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult(); ",
            "if($bytes.Length -eq 0 -or $bytes.Length -gt 262144){{throw '可信安装器大小无效'}}; ",
            "$s=Join-Path $d 'bootstrap.ps1'; [IO.File]::WriteAllBytes($s,$bytes); ",
            "if((Get-FileHash -LiteralPath $s -Algorithm SHA256).Hash -ine {hash}){{throw '可信安装器摘要不匹配'}} ",
            "}}finally{{$r.Dispose()}} }}finally{{$c.Dispose();$h.Dispose()}}; ",
            "& $s -Version {version} -Panel {panel} -Token {token} -Target {target} -Mirror {mirror} ",
            "}}finally{{Remove-Item -LiteralPath $d -Recurse -Force}}"
        ),
        url = quote(&bootstrap_url()),
        hash = quote(&checksum),
        version = quote(version),
        panel = quote(panel),
        token = quote(token),
        target = quote(target),
        mirror = quote(mirror),
    );
    let wrapper = format!(
        concat!(
            "$ErrorActionPreference='Stop'; $payload={program}; ",
            "$admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); ",
            "if($admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){{ ",
            "& ([ScriptBlock]::Create($payload)) ",
            "}}else{{ ",
            "$exe=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\\v1.0\\powershell.exe'; ",
            "$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload)); ",
            "$p=Start-Process -FilePath $exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -Wait -PassThru; ",
            "if($p.ExitCode -ne 0){{throw 'Agent 安装失败，请查看管理员 PowerShell 输出'}} }}"
        ),
        program = quote(&program)
    );
    format!(
        "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {}",
        encoded(&wrapper)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(value: &str) -> String {
        let bytes = STANDARD.decode(value).unwrap();
        String::from_utf16(
            &bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn windows_launcher_pins_bytes_and_encodes_literal_arguments_into_one_line() {
        let token = "quote'\n$([Environment]::Exit(61));";
        let command = command("latest", "https://panel.example.com", token, "auto");
        assert!(!command.contains(['\n', '\r']));
        let wrapper = decode(command.split_whitespace().last().unwrap());
        assert!(wrapper.contains("-Verb RunAs"));
        assert!(wrapper.contains(&bootstrap_url()));
        assert!(wrapper.contains(&format!("{:x}", Sha256::digest(BOOTSTRAP))));
        assert!(wrapper.contains("$h.UseProxy=$false; $h.AllowAutoRedirect=$false"));
        assert!(wrapper.contains("SetAccessRuleProtection($true,$false)"));
        assert!(wrapper.contains(&quote(token).replace('\'', "''")));
        assert!(wrapper.find("Get-FileHash").unwrap() < wrapper.find("& $s -Version").unwrap());
        assert!(command.len() < 32767);
        assert!(BOOTSTRAP.len() <= 262144);
    }

    #[test]
    fn windows_launcher_quotes_every_single_quote_delimiter_in_mirror_paths() {
        for character in ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'] {
            let value = format!(
                "https://mirror.example.com/{character};[Environment]::Exit(61);{character}tail"
            );
            let settings = crate::server_assets::AssetSettings {
                agent_mirror: value.clone(),
                ..Default::default()
            }
            .normalized()
            .unwrap();
            assert_eq!(settings.agent_mirror, value);
            let doubled = value.replace(character, &format!("{character}{character}"));
            assert_eq!(quote(&value), format!("'{doubled}'"));
            let command = command_with_mirror(
                "latest",
                "https://panel.example.com",
                "fixture",
                "auto",
                &value,
            );
            let wrapper = decode(command.split_whitespace().last().unwrap());
            let quoted_argument = quote(&value);
            let outer_literal = quote(&quoted_argument);
            assert!(wrapper.contains(&outer_literal[1..outer_literal.len() - 1]));
            assert!(command.len() < 32767);
        }
        let mirror = format!("https://mirror.example.com/{}", "\u{2019}".repeat(160));
        assert!(mirror.len() <= 512);
        let command = command_with_mirror(
            "latest",
            "https://panel.example.com",
            "fixture",
            "auto",
            &mirror,
        );
        assert!(command.len() < 32767);
    }
}
