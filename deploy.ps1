# Settings
$PROJECT_ID="maliev-website"
$ARTIFACT_NAME="maliev-authservice-api"
$ARTIFACT_TAG = "v" + (Get-Date -UFormat "%Y.%m.%d.%H%M")
$CLUSTER_NAME="web-production-cluster"
$ARTIFACT_LOCATION="asia-southeast1"
$ARTIFACT_REPOSITORY="maliev-website-artifact"

# Commands
Clear-Host
Start-Transcript -Path 'deploy.log'

# Replace container tag in deployment file
Write-Host Target container tag: $ARTIFACT_TAG
(Get-Content deployment.yaml).replace('##VERSION##', $ARTIFACT_TAG) | Set-Content deployment.yaml

Write-Host
Write-Host -------------------------------------------------------
Write-Host PREPERATION : Get Google Kubernetes cluster credentials
Write-Host -------------------------------------------------------
gcloud container clusters get-credentials $CLUSTER_NAME --zone $CLUSTER_ZONE 2> $null

Write-Host
Write-Host ---------------------------------------------------------------------------------
Write-Host PREPERATION : Authenticate Docker command-line tool to Google Artifact Registry
Write-Host ---------------------------------------------------------------------------------
gcloud auth configure-docker $ARTIFACT_LOCATION-docker.pkg.dev --quiet 2> $null
docker login $ARTIFACT_LOCATION-docker.pkg.dev
docker image prune -a -f

Write-Host
Write-Host -----------------------------------------
Write-Host STEP : Build and tag the Docker container
Write-Host -----------------------------------------
dotnet publish -c Release
docker build --file Dockerfile --tag $ARTIFACT_LOCATION-docker.pkg.dev/$PROJECT_ID/$ARTIFACT_REPOSITORY/${ARTIFACT_NAME}:$ARTIFACT_TAG .

Write-Host
Write-Host ----------------------------------------------------
Write-Host STEP : Upload the image to Google Artifact Registry
Write-Host ----------------------------------------------------
docker push $ARTIFACT_LOCATION-docker.pkg.dev/$PROJECT_ID/$ARTIFACT_REPOSITORY/${ARTIFACT_NAME}:$ARTIFACT_TAG

Write-Host
Write-Host -------------------------
Write-Host STEP : Deploy application
Write-Host -------------------------
kubectl apply -f deployment.yaml

Write-Host
Write-Host -------------------------------------------
Write-Host STEP: See the pod created by the deployment
Write-Host -------------------------------------------
kubectl get pods -n maliev

Write-Host
Write-Host -------------------------------------
Write-Host STEP : Get external IP of application
Write-Host -------------------------------------
kubectl get service -n maliev

Set-Location $PSScriptRoot

# Replace container tag in deployment file back to default
(Get-Content deployment.yaml).replace($ARTIFACT_TAG, '##VERSION##') | Set-Content deployment.yaml

Write-Host
Stop-Transcript