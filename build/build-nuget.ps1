. ./build-utils.ps1

dotnet pack  $arctiumSlnFilePath --configuration Release --output $nuget_output_directory /p:Version=1.0.0.1;
