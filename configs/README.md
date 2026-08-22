# Configs

`configs/` contains training and parser configuration.

## Files

- `drain3.ini`: Drain3 log-template parser settings.
- `data.yaml`: synthetic data and parser token settings.
- `train_hdfs.yaml`: HDFS-style training configuration.
- `train_openstack.yaml`: OpenStack-style training configuration.

These files are source configuration, not secrets. Generated datasets, tokenizer output, checkpoints, and experiment logs should stay outside Git.
