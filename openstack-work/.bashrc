alias docker="sudo docker"
alias bashrc="vim ~/.bashrc"
alias vi="vim"
alias reload="source ~/.bashrc"

# Add openstack.dev to /etc/hosts if not already present for local development
grep -q "openstack.local" /etc/hosts || echo "127.0.0.1 openstack.local" | sudo tee -a /etc/hosts