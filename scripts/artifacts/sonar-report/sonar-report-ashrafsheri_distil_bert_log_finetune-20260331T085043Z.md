# Sonar Report: `ashrafsheri_distil_bert_log_finetune`

- Generated: `2026-03-31T08:50:46.199734+00:00`
- Dashboard: https://sonarcloud.io/dashboard?id=ashrafsheri_distil_bert_log_finetune

## Metrics

- Quality Gate: `ERROR`
- Reliability Rating: `A`
- Security Rating: `A`
- Maintainability Rating: `A`
- Bugs: `0`
- Vulnerabilities: `0`
- Code Smells: `255`
- Security Hotspots: `154`
- Coverage: `3.5%`
- Duplicated Lines Density: `0.7%`
- Lines of Code: `25732`

## Quality Gate Conditions

- `new_reliability_rating`: status=`OK`, actual=`1`, threshold=`1`
- `new_security_rating`: status=`OK`, actual=`1`, threshold=`1`
- `new_maintainability_rating`: status=`OK`, actual=`1`, threshold=`1`
- `new_coverage`: status=`ERROR`, actual=`3.3`, threshold=`80`
- `new_duplicated_lines_density`: status=`OK`, actual=`2.3`, threshold=`3`
- `new_security_hotspots_reviewed`: status=`ERROR`, actual=`0.0`, threshold=`100`

## Issue Summary

- Total issues in selected statuses: `255`
- By severity: `{"CRITICAL": 67, "INFO": 1, "MAJOR": 152, "MINOR": 35}`
- By type: `{"CODE_SMELL": 255}`

### Top Rules

- `python:S3457`: `49`
- `python:S8415`: `32`
- `python:S1192`: `29`
- `python:S3776`: `23`
- `shelldre:S7688`: `11`
- `python:S5754`: `7`
- `python:S7503`: `7`
- `python:S125`: `6`
- `shelldre:S7682`: `6`
- `python:S6903`: `5`
- `shelldre:S7679`: `5`
- `typescript:S7764`: `5`
- `python:S1481`: `4`
- `python:S3358`: `4`
- `typescript:S7735`: `4`
- `python:S6983`: `4`
- `python:S1172`: `4`
- `python:S1871`: `4`
- `plsql:SelectStarCheck`: `3`
- `kubernetes:S6897`: `3`

## Security Hotspots

- Total hotspots returned: `155`
- By status: `{"REVIEWED": 1, "TO_REVIEW": 154}`

## Issues By File

### `ashrafsheri_distil_bert_log_finetune:backend/app/controllers/log_controller.py`

- [CRITICAL] `python:S1192` (line `78`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Project not found" 3 times.
- [CRITICAL] `python:S3776` (line `376`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 19 to the 15 allowed.
- [CRITICAL] `python:S3776` (line `528`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 17 to the 15 allowed.

### `ashrafsheri_distil_bert_log_finetune:backend/app/controllers/user_controller.py`

- [CRITICAL] `python:S3776` (line `21`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 37 to the 15 allowed.

### `ashrafsheri_distil_bert_log_finetune:backend/app/services/elasticsearch_service.py`

- [CRITICAL] `python:S3776` (line `210`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.
- [MAJOR] `python:S3358` (line `258`, type `CODE_SMELL`): Extract this nested conditional expression into an independent statement.
- [MINOR] `python:S7503` (line `75`, type `CODE_SMELL`): Use asynchronous features in this function or remove the `async` keyword.
- [MINOR] `python:S7503` (line `95`, type `CODE_SMELL`): Use asynchronous features in this function or remove the `async` keyword.
- [MINOR] `python:S7503` (line `146`, type `CODE_SMELL`): Use asynchronous features in this function or remove the `async` keyword.
- [MINOR] `python:S7503` (line `210`, type `CODE_SMELL`): Use asynchronous features in this function or remove the `async` keyword.
- [MINOR] `python:S7503` (line `283`, type `CODE_SMELL`): Use asynchronous features in this function or remove the `async` keyword.

### `ashrafsheri_distil_bert_log_finetune:backend/app/services/log_parser_service.py`

- [CRITICAL] `python:S3776` (line `29`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 28 to the 15 allowed.
- [CRITICAL] `python:S3776` (line `171`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.
- [CRITICAL] `python:S5754` (line `128`, type `CODE_SMELL`): Specify an exception class to catch or reraise the exception
- [CRITICAL] `python:S6903` (line `314`, type `CODE_SMELL`): Don't use `datetime.datetime.utcnow` to create this datetime object.

### `ashrafsheri_distil_bert_log_finetune:backend/app/services/log_service.py`

- [CRITICAL] `python:S1192` (line `387`, type `CODE_SMELL`): Define a constant instead of duplicating this literal '%d/%b/%Y:%H:%M:%S +0000' 3 times.
- [CRITICAL] `python:S3776` (line `261`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 124 to the 15 allowed.
- [CRITICAL] `python:S5754` (line `388`, type `CODE_SMELL`): Specify an exception class to catch or reraise the exception
- [INFO] `python:S1135` (line `35`, type `CODE_SMELL`): Complete the task associated to this "TODO" comment.
- [MAJOR] `python:S3457` (line `240`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `250`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `288`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `307`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `332`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `338`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `343`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `545`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MINOR] `python:S1481` (line `140`, type `CODE_SMELL`): Remove the unused local variable "user_role".
- [MINOR] `python:S1481` (line `164`, type `CODE_SMELL`): Remove the unused local variable "old_status".
- [MINOR] `python:S7503` (line `40`, type `CODE_SMELL`): Use asynchronous features in this function or remove the `async` keyword.

### `ashrafsheri_distil_bert_log_finetune:backend/app/services/report_service.py`

- [CRITICAL] `python:S3776` (line `262`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 19 to the 15 allowed.

### `ashrafsheri_distil_bert_log_finetune:backend/app/utils/firebase_auth.py`

- [MINOR] `python:S7503` (line `86`, type `CODE_SMELL`): Use asynchronous features in this function or remove the `async` keyword.

### `ashrafsheri_distil_bert_log_finetune:backend/migrations/001_add_model_tracking_to_orgs.sql`

- [CRITICAL] `plsql:S1192` (line `6`, type `CODE_SMELL`): Define a constant instead of duplicating this literal 3 times.

### `ashrafsheri_distil_bert_log_finetune:backend/migrations/001_organization_hierarchy.sql`

- [MAJOR] `plsql:SelectStarCheck` (line `10`, type `CODE_SMELL`): SELECT * should not be used.
- [MAJOR] `plsql:SelectStarCheck` (line `13`, type `CODE_SMELL`): SELECT * should not be used.

### `ashrafsheri_distil_bert_log_finetune:frontend/src/components/LogsTable.tsx`

- [CRITICAL] `typescript:S3776` (line `355`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 22 to the 15 allowed.
- [MAJOR] `typescript:S6479` (line `371`, type `CODE_SMELL`): Do not use Array index in keys
- [MAJOR] `typescript:S6479` (line `557`, type `CODE_SMELL`): Do not use Array index in keys

### `ashrafsheri_distil_bert_log_finetune:frontend/src/pages/AdminDashboardPage.tsx`

- [MINOR] `typescript:S7735` (line `218`, type `CODE_SMELL`): Unexpected negated condition.

### `ashrafsheri_distil_bert_log_finetune:frontend/src/pages/DashboardPage.tsx`

- [CRITICAL] `typescript:S3776` (line `13`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 17 to the 15 allowed.
- [MAJOR] `typescript:S125` (line `6`, type `CODE_SMELL`): Remove this commented out code.
- [MAJOR] `typescript:S125` (line `149`, type `CODE_SMELL`): Remove this commented out code.
- [MAJOR] `typescript:S125` (line `157`, type `CODE_SMELL`): Remove this commented out code.
- [MAJOR] `typescript:S3358` (line `724`, type `CODE_SMELL`): Extract this nested ternary operation into an independent statement.
- [MAJOR] `typescript:S3358` (line `765`, type `CODE_SMELL`): Extract this nested ternary operation into an independent statement.
- [MAJOR] `typescript:S6660` (line `294`, type `CODE_SMELL`): 'If' statement should not be the only statement in 'else' block
- [MAJOR] `typescript:S7762` (line `273`, type `CODE_SMELL`): Prefer `childNode.remove()` over `parentNode.removeChild(childNode)`.
- [MINOR] `typescript:S7735` (line `606`, type `CODE_SMELL`): Unexpected negated condition.
- [MINOR] `typescript:S7764` (line `266`, type `CODE_SMELL`): Prefer `globalThis` over `window`.
- [MINOR] `typescript:S7764` (line `274`, type `CODE_SMELL`): Prefer `globalThis` over `window`.

### `ashrafsheri_distil_bert_log_finetune:frontend/src/pages/ProjectMembersPage.tsx`

- [MINOR] `typescript:S4325` (line `154`, type `CODE_SMELL`): This assertion is unnecessary since it does not change the type of the expression.
- [MINOR] `typescript:S7735` (line `419`, type `CODE_SMELL`): Unexpected negated condition.

### `ashrafsheri_distil_bert_log_finetune:frontend/src/pages/ProjectsDashboard.tsx`

- [MINOR] `typescript:S7735` (line `407`, type `CODE_SMELL`): Unexpected negated condition.

### `ashrafsheri_distil_bert_log_finetune:frontend/src/pages/ReportsPage.tsx`

- [MAJOR] `typescript:S7762` (line `126`, type `CODE_SMELL`): Prefer `childNode.remove()` over `parentNode.removeChild(childNode)`.

### `ashrafsheri_distil_bert_log_finetune:frontend/src/pages/UsersPage.tsx`

- [MAJOR] `typescript:S3358` (line `228`, type `CODE_SMELL`): Extract this nested ternary operation into an independent statement.
- [MAJOR] `typescript:S6853` (line `370`, type `CODE_SMELL`): A form label must be associated with a control.
- [MINOR] `typescript:S7764` (line `83`, type `CODE_SMELL`): Prefer `globalThis` over `window`.

### `ashrafsheri_distil_bert_log_finetune:frontend/src/services/projectService.ts`

- [MINOR] `typescript:S4323` (line `63`, type `CODE_SMELL`): Replace this union type with a type alias.

### `ashrafsheri_distil_bert_log_finetune:frontend/src/utils/constants.ts`

- [MINOR] `typescript:S7764` (line `3`, type `CODE_SMELL`): Prefer `globalThis` over `window`.
- [MINOR] `typescript:S7764` (line `3`, type `CODE_SMELL`): Prefer `globalThis` over `window`.

### `ashrafsheri_distil_bert_log_finetune:frontend/src/utils/helpers.tsx`

- [MINOR] `typescript:S2486` (line `13`, type `CODE_SMELL`): Handle this exception or don't catch it at all.

### `ashrafsheri_distil_bert_log_finetune:integration_tests/ai_test_cases_integration_test.py`

- [CRITICAL] `python:S3776` (line `121`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 17 to the 15 allowed.
- [CRITICAL] `python:S6903` (line `103`, type `CODE_SMELL`): Don't use `datetime.datetime.utcnow` to create this datetime object.
- [MAJOR] `python:S125` (line `48`, type `CODE_SMELL`): Remove this commented out code.
- [MAJOR] `python:S125` (line `71`, type `CODE_SMELL`): Remove this commented out code.
- [MAJOR] `python:S125` (line `395`, type `CODE_SMELL`): Remove this commented out code.
- [MAJOR] `python:S3457` (line `150`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `190`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `326`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `327`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.

### `ashrafsheri_distil_bert_log_finetune:integration_tests/generate_stress_report.py`

- [CRITICAL] `python:S3776` (line `149`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 29 to the 15 allowed.
- [MAJOR] `python:S125` (line `49`, type `CODE_SMELL`): Remove this commented out code.
- [MAJOR] `python:S3457` (line `398`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MINOR] `python:S117` (line `55`, type `CODE_SMELL`): Rename this local variable "tcPr" to match the regular expression ^[_a-z][a-z0-9_]*$.
- [MINOR] `python:S117` (line `65`, type `CODE_SMELL`): Rename this local variable "tcPr" to match the regular expression ^[_a-z][a-z0-9_]*$.

### `ashrafsheri_distil_bert_log_finetune:integration_tests/selenium_integration_test.py`

- [CRITICAL] `python:S1192` (line `212`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "button[type='submit']" 9 times.
- [CRITICAL] `python:S1192` (line `325`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Navigating to /login" 5 times.
- [CRITICAL] `python:S1192` (line `348`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Clicking submit" 4 times.
- [CRITICAL] `python:S1192` (line `434`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Add New Organization" 5 times.
- [CRITICAL] `python:S1192` (line `435`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "arguments[0].scrollIntoView({block:'center'})" 13 times.
- [CRITICAL] `python:S1192` (line `437`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "arguments[0].click()" 13 times.
- [CRITICAL] `python:S1192` (line `456`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Opening form" 4 times.
- [CRITICAL] `python:S1192` (line `461`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "input[placeholder='Enter manager email']" 4 times.
- [CRITICAL] `python:S1192` (line `468`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Create Organization" 3 times.
- [CRITICAL] `python:S1192` (line `475`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "input[placeholder='Enter organization name']" 6 times.
- [CRITICAL] `python:S1192` (line `484`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "//button[contains(normalize-space(),'Cancel')]" 3 times.
- [CRITICAL] `python:S1192` (line `624`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "//h1[contains(text(),'Users Management')]" 4 times.
- [CRITICAL] `python:S1192` (line `665`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "//*[contains(text(),'Update User Role')]" 3 times.
- [CRITICAL] `python:S1192` (line `736`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "//tbody/tr" 5 times.
- [CRITICAL] `python:S1192` (line `870`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "No orgs present" 3 times.
- [CRITICAL] `python:S1192` (line `1021`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Depends on 6.1" 6 times.
- [CRITICAL] `python:S1192` (line `1145`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "//h2[contains(text(),'Recent Activity')]" 5 times.
- [CRITICAL] `python:S1192` (line `1160`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "//h1[contains(text(),'Security Dashboard')]" 3 times.
- [CRITICAL] `python:S1192` (line `1175`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "input[placeholder='e.g. 192.168.1.5']" 4 times.
- [CRITICAL] `python:S1192` (line `1177`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Clicking Search" 7 times.
- [CRITICAL] `python:S1192` (line `1327`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Export CSV" 3 times.
- [CRITICAL] `python:S1192` (line `1363`, type `CODE_SMELL`): Define a constant instead of duplicating this literal ".relative select" 3 times.
- [CRITICAL] `python:S3776` (line `615`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 73 to the 15 allowed.
- [CRITICAL] `python:S3776` (line `823`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 16 to the 15 allowed.
- [CRITICAL] `python:S3776` (line `1589`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.
- ... `8` more issue(s)

### `ashrafsheri_distil_bert_log_finetune:integration_tests/stress_test.py`

- [CRITICAL] `python:S1192` (line `205`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "application/json" 3 times.
- [CRITICAL] `python:S3776` (line `248`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 34 to the 15 allowed.
- [CRITICAL] `python:S6903` (line `127`, type `CODE_SMELL`): Don't use `datetime.datetime.utcnow` to create this datetime object.
- [CRITICAL] `python:S6903` (line `130`, type `CODE_SMELL`): Don't use `datetime.datetime.utcnow` to create this datetime object.
- [CRITICAL] `python:S6903` (line `372`, type `CODE_SMELL`): Don't use `datetime.datetime.utcnow` to create this datetime object.
- [MAJOR] `python:S125` (line `57`, type `CODE_SMELL`): Remove this commented out code.
- [MAJOR] `python:S125` (line `433`, type `CODE_SMELL`): Remove this commented out code.
- [MINOR] `python:S1481` (line `275`, type `CODE_SMELL`): Remove the unused local variable "e".

### `ashrafsheri_distil_bert_log_finetune:k8s/anomaly-detection-deployment.yaml`

- [MAJOR] `kubernetes:S6596` (line `26`, type `CODE_SMELL`): Use a specific version tag for the image instead of "latest".
- [MAJOR] `kubernetes:S6897` (line `25`, type `CODE_SMELL`): Specify a storage request for this container.

### `ashrafsheri_distil_bert_log_finetune:k8s/backend-deployment.yaml`

- [MAJOR] `kubernetes:S6596` (line `37`, type `CODE_SMELL`): Use a specific version tag for the image instead of "latest".
- [MAJOR] `kubernetes:S6897` (line `36`, type `CODE_SMELL`): Specify a storage request for this container.

### `ashrafsheri_distil_bert_log_finetune:k8s/frontend-deployment.yaml`

- [MAJOR] `kubernetes:S6596` (line `26`, type `CODE_SMELL`): Use a specific version tag for the image instead of "latest".
- [MAJOR] `kubernetes:S6897` (line `25`, type `CODE_SMELL`): Specify a storage request for this container.

### `ashrafsheri_distil_bert_log_finetune:migrations/002_project_roles_update.sql`

- [MAJOR] `plsql:SelectStarCheck` (line `11`, type `CODE_SMELL`): SELECT * should not be used.
- [MINOR] `plsql:OrderByExplicitAscCheck` (line `70`, type `CODE_SMELL`): Add ASC in order to make the order explicit.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/api/server.py`

- [CRITICAL] `python:S1192` (line `125`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Detector not initialized" 5 times.
- [MAJOR] `python:S8415` (line `125`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `150`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `168`, type `CODE_SMELL`): Document this HTTPException with status code 400 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `189`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `230`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `240`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/api/server_adaptive.py`

- [CRITICAL] `python:S1192` (line `125`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "Detector not initialized" 4 times.
- [MAJOR] `python:S3358` (line `174`, type `CODE_SMELL`): Extract this nested conditional expression into an independent statement.
- [MAJOR] `python:S8415` (line `125`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `156`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `186`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `207`, type `CODE_SMELL`): Document this HTTPException with status code 400 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `216`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/api/server_multi_tenant.py`

- [MAJOR] `python:S8415` (line `205`, type `CODE_SMELL`): Document this HTTPException with status code 403 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `314`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `339`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `350`, type `CODE_SMELL`): Document this HTTPException with status code 500 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `361`, type `CODE_SMELL`): Document this HTTPException with status code 400 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `374`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `403`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `409`, type `CODE_SMELL`): Document this HTTPException with status code 404 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `424`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `428`, type `CODE_SMELL`): Document this HTTPException with status code 404 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `465`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `475`, type `CODE_SMELL`): Document this HTTPException with status code 401 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `478`, type `CODE_SMELL`): Document this HTTPException with status code 400 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `502`, type `CODE_SMELL`): Document this HTTPException with status code 400 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `527`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `532`, type `CODE_SMELL`): Document this HTTPException with status code 401 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `586`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `599`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `615`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `637`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.
- [MAJOR] `python:S8415` (line `652`, type `CODE_SMELL`): Document this HTTPException with status code 503 in the "responses" parameter.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/api/start_multi_tenant.sh`

- [MAJOR] `shelldre:S7677` (line `48`, type `CODE_SMELL`): Redirect this error message to stderr (>&2).
- [MAJOR] `shelldre:S7688` (line `47`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/models/adaptive_detector.py`

- [CRITICAL] `python:S3776` (line `716`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.
- [CRITICAL] `python:S3776` (line `804`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 41 to the 15 allowed.
- [MAJOR] `python:S1871` (line `738`, type `CODE_SMELL`): Either merge this branch with the identical one on line "734" or change one of the implementations.
- [MAJOR] `python:S1871` (line `742`, type `CODE_SMELL`): Either merge this branch with the identical one on line "734" or change one of the implementations.
- [MAJOR] `python:S3358` (line `994`, type `CODE_SMELL`): Extract this nested conditional expression into an independent statement.
- [MAJOR] `python:S3457` (line `105`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `108`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `109`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `128`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `152`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `174`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `180`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `185`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `189`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `198`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `212`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `215`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `216`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `220`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `229`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `231`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `409`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `537`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `639`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `644`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- ... `3` more issue(s)

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/models/ensemble_detector.py`

- [CRITICAL] `python:S3776` (line `180`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 22 to the 15 allowed.
- [CRITICAL] `python:S5754` (line `223`, type `CODE_SMELL`): Specify an exception class to catch or reraise the exception
- [MAJOR] `python:S1066` (line `151`, type `CODE_SMELL`): Merge this if statement with the enclosing one.
- [MAJOR] `python:S1172` (line `138`, type `CODE_SMELL`): Remove the unused function parameter "method".
- [MAJOR] `python:S3457` (line `321`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MINOR] `python:S116` (line `175`, type `CODE_SMELL`): Rename this field "RE_IPv4" to match the regular expression ^[_a-z][_a-z0-9]*$.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/models/knowledge_distillation.py`

- [CRITICAL] `python:S3776` (line `263`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 28 to the 15 allowed.
- [MAJOR] `python:S3457` (line `494`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S6711` (line `467`, type `CODE_SMELL`): Use a "numpy.random.Generator" here instead of this legacy function.
- [MINOR] `python:S6983` (line `289`, type `CODE_SMELL`): Specify the `num_workers` parameter.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/models/multi_tenant_detector.py`

- [MAJOR] `python:S1172` (line `398`, type `CODE_SMELL`): Remove the unused function parameter "project_id".
- [MAJOR] `python:S3457` (line `93`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/models/project_manager.py`

- [MAJOR] `python:S3457` (line `139`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `278`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `299`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/models/student_model.py`

- [CRITICAL] `python:S3776` (line `286`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 44 to the 15 allowed.
- [MAJOR] `python:S1172` (line `573`, type `CODE_SMELL`): Remove the unused function parameter "session_stats".
- [MAJOR] `python:S3457` (line `481`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S6973` (line `383`, type `CODE_SMELL`): Add the missing hyperparameter weight_decay for this PyTorch optimizer.
- [MAJOR] `pythonenterprise:S7708` (line `422`, type `CODE_SMELL`): Collect tensors in a list and concatenate once outside the loop to improve performance.
- [MINOR] `python:S6983` (line `379`, type `CODE_SMELL`): Specify the `num_workers` parameter.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/models/teacher_model.py`

- [CRITICAL] `python:S3776` (line `126`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 16 to the 15 allowed.
- [CRITICAL] `python:S3776` (line `538`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 24 to the 15 allowed.
- [MAJOR] `python:S1172` (line `418`, type `CODE_SMELL`): Remove the unused function parameter "session_stats".
- [MAJOR] `python:S1871` (line `260`, type `CODE_SMELL`): Either merge this branch with the identical one on line "257" or change one of the implementations.
- [MAJOR] `python:S3457` (line `641`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S6973` (line `598`, type `CODE_SMELL`): Add the missing hyperparameter weight_decay for this PyTorch optimizer.
- [MINOR] `python:S6983` (line `594`, type `CODE_SMELL`): Specify the `num_workers` parameter.

### `ashrafsheri_distil_bert_log_finetune:realtime_anomaly_detection/streaming/log_streamer.py`

- [CRITICAL] `python:S3776` (line `102`, type `CODE_SMELL`): Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.
- [MAJOR] `python:S1871` (line `169`, type `CODE_SMELL`): Either merge this branch with the identical one on line "166" or change one of the implementations.
- [MAJOR] `python:S3457` (line `55`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MINOR] `python:S1481` (line `123`, type `CODE_SMELL`): Remove the unused local variable "color".

### `ashrafsheri_distil_bert_log_finetune:scripts/k8s-deploy.sh`

- [MAJOR] `shelldre:S7677` (line `23`, type `CODE_SMELL`): Redirect this error message to stderr (>&2).
- [MAJOR] `shelldre:S7682` (line `21`, type `CODE_SMELL`): Add an explicit return statement at the end of the function.
- [MAJOR] `shelldre:S7682` (line `22`, type `CODE_SMELL`): Add an explicit return statement at the end of the function.
- [MAJOR] `shelldre:S7682` (line `23`, type `CODE_SMELL`): Add an explicit return statement at the end of the function.

### `ashrafsheri_distil_bert_log_finetune:scripts/log_generator.py`

- [CRITICAL] `python:S1192` (line `191`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "/api/gcp" 7 times.
- [CRITICAL] `python:S1192` (line `296`, type `CODE_SMELL`): Define a constant instead of duplicating this literal "/api/mxfunnel/submit" 3 times.
- [CRITICAL] `python:S5754` (line `198`, type `CODE_SMELL`): Specify an exception class to catch or reraise the exception
- [CRITICAL] `python:S5754` (line `246`, type `CODE_SMELL`): Specify an exception class to catch or reraise the exception
- [CRITICAL] `python:S5754` (line `273`, type `CODE_SMELL`): Specify an exception class to catch or reraise the exception
- [CRITICAL] `python:S5754` (line `303`, type `CODE_SMELL`): Specify an exception class to catch or reraise the exception
- [MAJOR] `python:S3457` (line `507`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.
- [MAJOR] `python:S3457` (line `533`, type `CODE_SMELL`): Add replacement fields or use a normal string instead of an f-string.

### `ashrafsheri_distil_bert_log_finetune:scripts/monitor.sh`

- [MAJOR] `shelldre:S7688` (line `36`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.
- [MAJOR] `shelldre:S7688` (line `47`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.
- [MAJOR] `shelldre:S7688` (line `60`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.
- [MINOR] `shelldre:S1192` (line `77`, type `CODE_SMELL`): Define a constant instead of using the literal '==========================================' 5 times.

### `ashrafsheri_distil_bert_log_finetune:scripts/preflight_check.sh`

- [MAJOR] `shelldre:S7679` (line `14`, type `CODE_SMELL`): Assign this positional parameter to a local variable.
- [MAJOR] `shelldre:S7679` (line `15`, type `CODE_SMELL`): Assign this positional parameter to a local variable.
- [MAJOR] `shelldre:S7679` (line `18`, type `CODE_SMELL`): Assign this positional parameter to a local variable.
- [MAJOR] `shelldre:S7679` (line `20`, type `CODE_SMELL`): Assign this positional parameter to a local variable.
- [MAJOR] `shelldre:S7679` (line `21`, type `CODE_SMELL`): Assign this positional parameter to a local variable.
- [MAJOR] `shelldre:S7682` (line `13`, type `CODE_SMELL`): Add an explicit return statement at the end of the function.
- [MAJOR] `shelldre:S7688` (line `14`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.
- [MAJOR] `shelldre:S7688` (line `20`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.
- [MAJOR] `shelldre:S7688` (line `59`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.
- [MAJOR] `shelldre:S7688` (line `60`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.
- [MAJOR] `shelldre:S7688` (line `108`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.
- [MAJOR] `shelldre:S7688` (line `108`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.
- [MAJOR] `shelldre:S7688` (line `126`, type `CODE_SMELL`): Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich.
- [MINOR] `shelldre:S1192` (line `119`, type `CODE_SMELL`): Define a constant instead of using the literal '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' 5 times.

### `ashrafsheri_distil_bert_log_finetune:scripts/production_run.sh`

- [MINOR] `shelldre:S1192` (line `26`, type `CODE_SMELL`): Define a constant instead of using the literal '==========================================' 4 times.

### `ashrafsheri_distil_bert_log_finetune:scripts/upload-model-artifacts.sh`

- [MAJOR] `shelldre:S7677` (line `20`, type `CODE_SMELL`): Redirect this error message to stderr (>&2).
- [MAJOR] `shelldre:S7682` (line `19`, type `CODE_SMELL`): Add an explicit return statement at the end of the function.
- [MAJOR] `shelldre:S7682` (line `20`, type `CODE_SMELL`): Add an explicit return statement at the end of the function.
