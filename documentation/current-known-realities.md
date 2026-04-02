# Current Known Realities

This file captures code-grounded and operations-grounded realities that matter when working with the repository today.

## 1. The detector is a hybrid system, not a pure ML classifier

The running detector combines:

- hard rule-based attack checks
- transformer sequence novelty
- Isolation Forest feature-based scoring

Known exploit behavior is still most reliably caught by the rules layer.

## 2. Warmup quality is weaker than active student quality

During project warmup the teacher path is used. In practice that means:

- cold-start quality depends on base artifacts and saved teacher state
- project-specific vocab and history are not fully available yet
- low-traffic projects benefit from the `low_traffic` profile and manifest seeding

## 3. Unknown templates are a real source of low-signal scores

Teacher and student transformer paths now suppress low-quality sequence scores when too much of the sequence is unknown, but this is still a sign that the detector lacks route knowledge for the project.

## 4. The detector and backend are separate deployable services

If the backend image updates but the anomaly service does not, behavior will diverge. The same is true in reverse.

## 5. Git pull on a server is not the same as a deployment

This repository is containerized. Pulling new code into a server checkout does not update the code already baked into running images.

## 6. SQL migrations are not automatically applied by startup

If code adds a new relational field, the database must be migrated separately.

## 7. Fluent Bit config in the repo is not generic

The checked-in Fluent Bit file contains:

- hardcoded Windows paths
- a hardcoded host
- a hardcoded API key
- repeated sections

Treat it as a concrete environment config, not a clean universal template.

## 8. Kubernetes manifests still use placeholder GHCR image paths

The checked-in manifests reference images like:

- `ghcr.io/OWNER/backend:main`

Production deployment therefore depends on CI or some templating/substitution step outside the plain YAML files.

## 9. Detector state quality depends on PVC contents

The anomaly service can be operational while still being partially degraded if:

- base artifacts are incomplete
- teacher IF is missing or unfitted
- saved state is stale

Startup logs are the authoritative check.

## 10. Endpoint manifest seeding is now a real first-class feature

This is not just a design note. The repo now contains:

- an external route extractor script
- a backend seed endpoint
- detector-side manifest-aware normalization and probe classification

That path is one of the most concrete improvements available for low-traffic cold-start projects.
