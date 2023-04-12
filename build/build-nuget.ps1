. ./build-utils.ps1

dotnet pack  $arctiumSlnFilePath --configuration Release --output $nuget_output_directory;
