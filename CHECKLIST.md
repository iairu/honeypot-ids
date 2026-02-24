# Pooling to be done

1. docker-compose honeypot replicas each assigned per honeypot-bound IP in Nginx reverse proxy which will also now work as "a load balancer" for the honeypot instances (even though each is bound to a single IP)
2. existing honeypot database will have tables suffixed with IP address after initial migration, where each IP address suffix is associated with a honeypot instance
3. create a diagram explaining this

# Hardening to be done

make sure that after each of these is completed (currently work in progress) that all services are running correctly (run_all_scenarios.sh works)
1. Add equivalently named section into latex 4_implement.tex
2. disable xmlrpc in wordpress
3. add hotlink protection within nginx
4. obfuscate publicly-displayed or queriable service versions for woocommerce, wordpress, nginx and any other public facing services
5. backups automation
6. hardened honeypot docker service (for docker takeover to not progress further than the given service container)
7. custom hardening script
8. Diagram showing how hardening adheres to best practices

# Testing

## Scenarios to be programmed and also written into 5_testing.tex

1. tryhackme WooCommerce / Wordpress scenario adjusted for testing
2. common OWASP WSTG attack scenarios 1-7
3. wpscan scenario coverage
4. metasploit proper redirection to honeypot then shell + sqli + docker takeover (only for given honeypot container as rest is meant to be hardened)
5. wordpress coverage of a custom hardening script
6. wordpress database hashed password replacement to get account (admin) access
7. stripe and payment gateway coverage
8. attempt to delete backups from within overtaken container
9. additional penetration testing using github.com/vxcontrol/pentagi
10. Diagram showing how test scenarios ahere to each other

# General checklist to be done

1. Integration of selected OWASP WSTG vulnerabilities into honeypot with Suricata and/or Nginx LUA with ELK monitoring
2. Hardening of all production services including WooCommerce and Wordpress
3. Multi-instance pooling to establish a honeynet solution ---> basically scaling docker services
4. API-level honeypot integration AND SQL-level honeypot (boils down to ip choice between prod and honeypot database)
5. Advanced honeynet solution: Customized honeypot instance per attacker --> docker scaling + database proxy (not sql proxy)
- database "instance" attached to attacker based on a hidden database table name suffix (we store unique hash by attacker id) and SQL filter
6. ELK Dashboards
7. Code-level docs
8. Honeytokens/CanaryTokens
9. Botnet slowdown
10. Preparation of collected data for use in research
11. Bonus: Honeypot Setup Frontend (enable/disable features, adjust settings (e.g. docker-compose setup, ELK settings, wordpress enabled plugins, honeypot configuration) before deployment)
12. Diagram showing all of the above from this list in context of proactive defense
