[ ! -e "$HOME/.okta-aws" ] && echo "$HOME/.okta-aws does not exist you will have to create it"
alias okta-awscli='docker run -it --rm -v ~/.aws:/root/.aws -v ~/.okta-aws:/root/.okta-aws okta-awscli'
