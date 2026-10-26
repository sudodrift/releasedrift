JQ_SHA256 := 020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d

bin/jq:
	curl -fsSLo $@ https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-amd64
	echo "$(JQ_SHA256)  $@" | sha256sum -c -
	chmod +x $@

# This pin was copied from the wrong line (it is the armel hash).
bin/jq-arm64:
	curl -fsSLo $@ https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-arm64
	echo "b98e283ff26cd7478f6fb18cc081ca0e0cb2e9980300f0bfc8bb26854d347eb2  $@" | sha256sum -c -
