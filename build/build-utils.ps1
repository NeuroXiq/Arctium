# File contains utilities 
# used by build scripts
# paths, functions etc. to have in one place
#

$arctiumSlnFilePath = '../src/Arctium/Arctium.sln' | convert-path;
$buildBinArtifactsDir = join-path $(pwd) -childpath '/build-bin-artifacts';

function util_zipFiles( $zipfilename, $sourcedir )
{
   Add-Type -Assembly System.IO.Compression.FileSystem
   $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
   [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir,
        $zipfilename, $compressionLevel, $false)
}