all: build
build: attack-build setup-build defense-build

target: FORCE
	@rm -rf target
	@mkdir -p target/attack
	@mkdir -p target/defense 
	@mkdir -p target/setup
FORCE: 

setups = client bombast-resolver external-web root-dns vpn-host zoo-dns
$(setups): %: target
	dpkg-deb --build ./setup/$* ./target/setup/$*-setup.deb
setup-build: $(setups)

attacks = dns-iptables-block  # TODO: This should really be a command line thing maybe? Not a package...
$(attacks): %: target
	dpkg-deb --build ./attack/$* ./target/attack/$*.deb
attack-build: $(attacks)

defenses = root-dnssec zoo-dnssec client-resolver vpn-client

$(defenses): %: target
	dpkg-deb --build ./defense/$* ./target/defense/$*.deb
defense-build: $(defenses)

deploy: build
	./deploy

demo: 
	./demo_attack

report: report.md references.bib | target
	pandoc -H report.css -s report.md -o target/report.html

check: 
	shellcheck deploy verify_hosts demo_attack

clean: 
	@rm -rf target

.PHONY: $(attacks) $(defenses) $(setups) report clean all deploy demo
