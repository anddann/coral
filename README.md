# Coral
This is the source code for the reproduction of Coral published at ICSE23

Because the project was initially developed based on an external database, MongoDB. Given its large volume and commercial confidentiality, I am not releasing it in this repo. You are most welcome to contact me for the up-to-date databases at `lyuyezhang@gmail.com`.


## Reproduction
To allow a lightweight reproduction, I have removed the dependence on MongoDB, but read from multiple CSV files. You are free to populate the CSV files with your own data in the same format.
Please note that the vulnerability mappings in vulnerabilities/vul_edges_unique.csv and cve_func_10_22.csv are not included with full data, as these contain commercialized data. 

To run the system, the main entry point is in `production_entry.py`. Simply replace the example arguments in the product_remediation function with your own projects with dependency trees in the same format and the Maven project path. The required Python dependencies are listed in requirements.txt. You should be able to start the system by running:
```
python production_entry.py
```
(no CLI arguments are needed).


## Dependencies
1. This package depends on a Maven semver RESTful API, which is provided separately in `maven_semver`. Please refer to the `README.md` in that folder to initialize the service via Docker.
2. This project depends on [revapi](https://revapi.org/revapi-site/main/index.html) which is already included in the repository.
3. This project's program analysis part is built on [Soot](https://soot-oss.github.io/soot/). 
