project_name: "network_security"

constant: GCP_PROJECT {
  value: "mi-proyecto-poc"
  export: override_optional
}

constant: BQ_DATASET {
  value: "network_logs"
  export: override_optional
}
