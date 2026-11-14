# HomeXDR agent installer for Windows (Windows PowerShell 5.1 or PowerShell 7, run as
# administrator). The console's one-line command downloads this script and runs it with:
#   -Token <enrollment token> -CaPin sha256:<hex> [-Labels a,b] [-InstallDir <folder>]
# It checks the server's CA against the pin before downloading anything else, so the agent
# is fetched over a verified TLS connection and checked against SHA256SUMS. Fetching this
# script itself is the one unverified step; to avoid it, download the script once and review
# it, or copy the agent binary manually.
param(
  [Parameter(Mandatory = $true)][string]$Token,
  [Parameter(Mandatory = $true)][string]$CaPin,
  [string]$Labels = '',
  [string]$Server = '__SERVER__',
  [string]$InstallDir = (Join-Path $env:ProgramFiles 'HomeXDR')
)
$ErrorActionPreference = 'Stop'
function Fail([string]$msg) { throw "homexdr: $msg" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Fail 'run this from PowerShell opened with "Run as administrator"'
}
if (-not [Environment]::Is64BitOperatingSystem) { Fail 'the agent needs 64-bit Windows' }
$Server = $Server.TrimEnd('/')
$bin = 'homexdr-agent-windows-amd64.exe'

# Downloads go through HttpClient with a certificate check written in C#: with no CA set it
# accepts any certificate (only for fetching the CA itself); once the pinned CA is set, the
# server must chain to exactly that CA and match the host name.
$src = @'
using System;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
namespace HomeXDRInstall {
  public static class Fetch {
    public static X509Certificate2 Ca;
    static bool Check(HttpRequestMessage m, X509Certificate2 cert, X509Chain chain, SslPolicyErrors errors) {
      if (cert == null) return false;
      if (Ca == null) return true;
      if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
      X509Chain c = new X509Chain();
      c.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
      c.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
      c.ChainPolicy.ExtraStore.Add(Ca);
      if (!c.Build(cert)) return false;
      byte[] root = c.ChainElements[c.ChainElements.Count - 1].Certificate.RawData;
      byte[] want = Ca.RawData;
      if (root.Length != want.Length) return false;
      for (int i = 0; i < root.Length; i++) { if (root[i] != want[i]) return false; }
      return true;
    }
    public static void Download(string url, string path) {
      HttpClientHandler h = new HttpClientHandler();
      h.ServerCertificateCustomValidationCallback = Check;
      using (HttpClient client = new HttpClient(h)) {
        client.Timeout = TimeSpan.FromMinutes(10);
        using (HttpResponseMessage r = client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult()) {
          if (!r.IsSuccessStatusCode) throw new Exception(url + ": HTTP " + (int)r.StatusCode + " " + r.ReasonPhrase);
          using (FileStream f = File.Create(path)) { r.Content.CopyToAsync(f).GetAwaiter().GetResult(); }
        }
      }
    }
  }
}
'@
if (-not ('HomeXDRInstall.Fetch' -as [type])) {
  if ($PSEdition -eq 'Core') { Add-Type -TypeDefinition $src }
  else { Add-Type -TypeDefinition $src -ReferencedAssemblies System.Net.Http }
}
function Get-File([string]$name, [string]$path) {
  try { [HomeXDRInstall.Fetch]::Download("$Server/v1/$name", $path) }
  catch {
    $e = $_.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    Fail "cannot download $name from ${Server}: $($e.Message)"
  }
}
function Get-Sha256([byte[]]$data) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($data)) -replace '-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('homexdr-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  # 1. Fetch the CA and check it against the pin.
  [HomeXDRInstall.Fetch]::Ca = $null
  Get-File 'ca.crt' (Join-Path $tmp 'ca.crt')
  $ca = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (Join-Path $tmp 'ca.crt')
  $got = 'sha256:' + (Get-Sha256 $ca.RawData)
  if ($got -ne $CaPin.Trim().ToLowerInvariant()) { Fail "CA pin mismatch: server presented $got" }

  # 2. Download the agent over verified TLS and check its checksum.
  [HomeXDRInstall.Fetch]::Ca = $ca
  Get-File "download/$bin" (Join-Path $tmp $bin)
  Get-File 'download/SHA256SUMS' (Join-Path $tmp 'SHA256SUMS')
  $want = $null
  foreach ($line in Get-Content (Join-Path $tmp 'SHA256SUMS')) {
    $f = $line -split '\s+', 2
    if ($f.Count -eq 2 -and $f[1].TrimStart('*') -eq $bin) { $want = $f[0].ToLowerInvariant() }
  }
  if (-not $want) { Fail "$bin is not listed in SHA256SUMS" }
  $have = Get-Sha256 ([IO.File]::ReadAllBytes((Join-Path $tmp $bin)))
  if ($have -ne $want) { Fail "checksum mismatch for $bin" }

  # 3. Install, enroll and start the service. A running agent is stopped first so its
  # binary can be replaced.
  $svc = Get-Service -Name 'HomeXDRAgent' -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service -Name 'HomeXDRAgent' -Force }
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  $exe = Join-Path $InstallDir 'homexdr-agent.exe'
  Copy-Item -LiteralPath (Join-Path $tmp $bin) -Destination $exe -Force
  $agentArgs = @('install', '--server', $Server, '--token', $Token, '--ca-pin', $CaPin)
  if ($Labels) { $agentArgs += @('--labels', $Labels) }
  & $exe @agentArgs
  if ($LASTEXITCODE -ne 0) { Fail "homexdr-agent install failed (exit code $LASTEXITCODE)" }
  Write-Host "homexdr: agent installed to $exe and enrolled"
}
finally {
  [HomeXDRInstall.Fetch]::Ca = $null
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
