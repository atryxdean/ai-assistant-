ML dataset for engin33r

This small CSV is intended as a tiny, curated training and evaluation set for local experiments. It is NOT representative of production data and is provided only for reproducible local testing and CI smoke-tests.

Format
- CSV with two columns: `text` and `label`
- `text`: short code snippet or evidence string
- `label`: vulnerability label matching engin33r.core.vulnerability.VulnerabilityType values (use the enum value strings)

Labels used in this sample:
- injection
- cross_site_scripting
- broken_authentication
- sensitive_data_exposure
- broken_access_control
- information_disclosure
- logic_error
- xml_external_entities
- insecure_deserialization
- dependency_vulnerability

License
- This dataset is licensed MIT alongside the repository. If you add real training data, ensure it is appropriately licensed and cleansed of secrets.
