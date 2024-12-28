# Vulboard: Vulnerability Management Tool

Vulboard is a custom-built vulnerability management tool designed to streamline the process of tracking, evaluating, and reporting security vulnerabilities. It integrates seamlessly with tools like Trivy, Prometheus, and Grafana to provide actionable insights and enhance your organization’s security posture.

## Key Features

- **Vulnerability Tracking**: Automatically tracks CVEs, updating their status based on scan results.
- **Prioritization**: Displays Exploit Prediction Scoring System (EPSS) scores to help prioritize vulnerabilities by exploitability.
- **Patch Information**: Provides vendor-specific patch details, including patch availability and versioning.
- **Metrics Export**: Processes scan results and exports them as Prometheus metrics for reporting.
- **Integration**: Supports integration with Trivy and GitHub workflows for automated vulnerability scanning and reporting.

## Deployment

### Prerequisites

1. **Kubernetes Cluster**: Access to a Kubernetes cluster.
2. **Helm**: Install Helm on your system. [Helm Installation Guide](https://helm.sh/docs/intro/install/)
3. **Git**: Ensure Git is installed.
4. **Trivy**: For vulnerability scanning.

### Deployment Steps

1. **Clone the Repository**

   ```bash
   git clone https://github.com/<your-repo-name>/vulboard-helm-chart.git
   cd vulboard-helm-chart
   ```

2. **Configure the Helm Chart**
   - Edit the `values.yaml` file to configure database settings, external services, and resource limits.

   ```bash
   nano values.yaml
   ```

3. **Install the Helm Chart**

   ```bash
   helm install vulboard ./vulboard-helm-chart
   ```

4. **Verify the Deployment**
   ```bash
   kubectl get pods
   kubectl get services
   ```

5. **Access Vulboard**
   - If using a LoadBalancer or NodePort service, get the external IP or port:
     ```bash
     kubectl get svc
     ```
   - If using Ingress, ensure DNS is configured correctly.

6. **Uninstall Vulboard** (Optional)
   ```bash
   helm uninstall vulboard
   ```

## Integration with Trivy and GitHub Workflow

Vulboard supports automated vulnerability scanning and reporting via GitHub workflows.

### Example GitHub Workflow

```yaml
name: Scan Docker Image in GHCR

on:
  push:
    branches:
      - master
  pull_request:
    branches:
      - master

jobs:
  scan-docker-image:
    name: Trivy Scan Docker Image
    runs-on: ubuntu-latest

    steps:
    - name: Checkout Code
      uses: actions/checkout@v3

    - name: Log in to GitHub Container Registry
      env:
        CR_PAT: ${{ secrets.GHCR_PAT }}
      run: |
        echo "$CR_PAT" | docker login ghcr.io -u $GITHUB_ACTOR --password-stdin

    - name: Scan Docker Image with Trivy Action
      uses: aquasecurity/trivy-action@0.28.0
      with:
        image-ref: "nginx"
        format: "template"
        template: "@trivy-format.tmpl"
        output: "trivy_report.json"

    - name: Upload CVE Report to API
      env:
        API_URL: ${{ secrets.API_URL }}
      run: |
        curl -X POST -H "Content-Type: application/json" --data @trivy_report.json $API_URL

    - name: Confirm Upload
      run: echo "CVE report uploaded successfully to ${{ secrets.API_URL }}"
```

### Steps to Set Up the Workflow

1. Create the workflow file in `.github/workflows/trivy-scan.yml`.
2. Add GitHub secrets for `GHCR_PAT` (GitHub PAT) and `API_URL` (Vulboard API URL).
3. Commit and push the changes to trigger the workflow.

## Metrics and Dashboards

Vulboard integrates with Prometheus and Grafana to provide:

- Vulnerability KPIs and trends.
- Closed CVEs tracking.
- EPSS-based prioritization insights.

### Configuring Prometheus and Grafana

1. Ensure Prometheus is running in your cluster.
2. Set Vulboard’s metrics endpoint in Prometheus:
   ```yaml
   scrape_configs:
     - job_name: 'vulboard'
       static_configs:
         - targets: ['<vulboard-service>:<port>']
   ```
3. Import the Vulboard Grafana dashboard JSON file into Grafana to visualize metrics.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve Vulboard.

## License

This project is licensed under the [MIT License](LICENSE).

---

For detailed documentation, visit the [Vulboard GitHub Repository](https://github.com/<your-repo-name>).
