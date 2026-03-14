$ErrorActionPreference = "Stop";

#$outName = "arctium-$([datetimeoffset]::now.tostring('yyyy_MM_ddTHH_mm_ss'))";
$projectPath = "$PSScriptRoot/../src/Arctium/Arctium/Arctium.csproj";
$output = "$PSScriptRoot/build-nuget-artifacts"
$apiKey = (get-content "$PSScriptRoot/../../../secrets/arctium-nuget-api-key.txt").trim();

if ([system.string]::IsNullOrWhiteSpace($apiKey)) {
    throw 'no nuget api key'
}

$curVersion = (get-content "$PSScriptRoot/version.txt").trim().split('.');
$nextVersion = "$($curVersion[0]).$($curVersion[1]).$([system.int32]::parse($curVersion[2]) + 1)"
set-content -path "$PSScriptRoot/version.txt" -value $nextVersion

'starting push new version.txt to remote repo'

git add version.txt
git commit -m 'publish-nuget: updated version.txt to next version'
git push

$nupkgFilePath = "$output/Arctium.$nextVersion.nupkg";

$nextVersion;
$outName;
$nupkgFilePath;

dotnet pack  $projectPath --configuration Release --output $output /p:Version=$nextVersion;
dotnet nuget push $nupkgFilePath --api-key $apiKey --source https://api.nuget.org/v3/index.json