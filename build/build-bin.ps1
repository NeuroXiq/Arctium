# build Arctium as dll libraries
#
# parameters: 
#

. ./build-utils.ps1

$nextNo = (gci $buildBinArtifactsDir).count;
$workingDirName = 'arctium-{0}_{1}' -f $nextNo, (get-date -format 'yyyy_MM_dd_HH_mm_ss').tostring()
$workingDir = join-path $buildBinArtifactsDir -childpath $workingDirName

#echo $workingDir
new-item $workingDir -type directory


$args = 
'{0} {1} {2} {3} ' -f `
(' publish "{0}"' -f $arctiumSlnFilePath), `
' --configuration Release', `
(' --output {0}' -f $workingDir), `
'  --verbosity n'

$props = 
'{0} {1} {2} {3} {4} {5}' -f `
'/p:Copyright="Arctium .NET Core Crypto Library" ', `
'/p:Product="Arctium .NET Core Crypto Library" ', `
'/p:AssemblyVersion=0.0.0.9 ', `
'/p:Version=0.0.0.9 ', `
'/p:Description="Arctium - .NET Core Crypto library"', `
'/p:Company="NeuroXiq"'

$args = ('{0} {1}' -f $args, $props);

#echo $args

#cls
start-process dotnet -argumentlist $args -nonewwindow

$zipFullFilePath = ('{0}-bin.zip' -f $workingDir);

#echo $zipFullFilePath
#echo $workingDir;
#pwd

#wait because compression doesnt work immediately (empty zip file when no sleep)
start-sleep -seconds 2
util_zipFiles $zipFullFilePath $workingDir
