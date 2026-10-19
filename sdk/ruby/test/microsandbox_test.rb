# frozen_string_literal: true

require "rbconfig"
require "test/unit"
require "timeout"
require_relative "../lib/microsandbox"

class MicrosandboxTest < Test::Unit::TestCase
  # Mirrors sdk/python/microsandbox/errors.py plus the Go SDK's snapshot,
  # exec-failed, and volume-already-exists granularity.
  ERROR_CLASSES = %i[
    RuntimeNotInstalledError RuntimeIncompleteError
    InvalidConfigError NoDefaultCommandError
    SandboxNotFoundError SandboxNotRunningError SandboxAlreadyExistsError SandboxReplacedError
    SandboxStillRunningError SandboxStopTimedOutError StopTimeoutError
    ExecTimeoutError ExecFailedError
    FilesystemError PathNotFoundError
    VolumeNotFoundError VolumeAlreadyExistsError ImageNotFoundError ImageInUseError ImagePullFailedError
    SnapshotNotFoundError SnapshotAlreadyExistsError SnapshotSandboxRunningError
    SnapshotImageMissingError SnapshotIntegrityError SnapshotSourceRecoveryError SnapshotMigrationError
    NetworkPolicyError SecretViolationError TlsError
    IoError
    MetricsDisabledError MetricsUnavailableError
    UnsupportedOperationError CloudHttpError UnsupportedError
  ].freeze

  def test_version_is_available
    assert_match(/\A\d+\.\d+\.\d+\z/, Microsandbox.version)
  end

  def test_installation_probe_returns_boolean
    assert_includes [true, false], Microsandbox.installed?
  end

  def test_builder_configuration_is_chainable
    proxy = Microsandbox::OutboundProxy.socks5("127.0.0.1:1080")
      .credentials("sandbox", Microsandbox::SecretSource.env("SOCKS5_PASSWORD"))

    builder = Microsandbox::Sandbox.builder("ruby-test")
      .image("alpine")
      .cpus(2)
      .memory(256)
      .env("GREETING", "hello")
      .label("suite", "ruby")
      .workdir("/tmp")
      .proxy(proxy)
      .vsock("/run/host-api.sock", 5000)
      .vsock_dgram("/run/events.sock", 5001)

    assert_instance_of Microsandbox::SandboxBuilder, builder
  end

  def test_socks4_proxy_user_id_is_chainable
    proxy = Microsandbox::OutboundProxy.socks4("127.0.0.1:1080").user_id("sandbox")

    assert_instance_of Microsandbox::OutboundProxy, proxy
  end

  def test_proxy_authentication_is_protocol_specific
    password = Microsandbox::SecretSource.env("SOCKS5_PASSWORD")

    assert_raise(ArgumentError) do
      Microsandbox::OutboundProxy.socks4("127.0.0.1:1080").credentials("sandbox", password)
    end
    assert_raise(ArgumentError) do
      Microsandbox::OutboundProxy.socks5("127.0.0.1:1080").user_id("sandbox")
    end
  end

  def test_secret_source_rejects_an_empty_environment_variable
    assert_raise(ArgumentError) { Microsandbox::SecretSource.env("") }
  end

  def test_secret_allowed_hosts_build_one_entry_with_every_host
    script = <<~RUBY
      require "json"
      require "socket"
      require "microsandbox"
      server = TCPServer.new("127.0.0.1", 0)
      capture = Thread.new do
        client = server.accept
        head = +""
        head << client.gets until head.end_with?("\\r\\n\\r\\n")
        body = client.read(head[/content-length: (\\d+)/i, 1].to_i)
        client.write("HTTP/1.1 500 Internal Server Error\\r\\ncontent-length: 0\\r\\nconnection: close\\r\\n\\r\\n")
        client.close
        body
      end
      Microsandbox.use_cloud_backend!("test-key", url: "http://127.0.0.1:\#{server.addr[1]}")
      begin
        Microsandbox::Sandbox.create("ruby-test", image: "alpine", secrets: [
          { env: "GITHUB_TOKEN", value: "token", allowed_hosts: ["github.com", "*.githubusercontent.com"] },
          { env: "API_KEY", value: "key", allowed_host: "api.example.com" },
          { env: "ANY_HOST_KEY", value: "any", allowed_hosts: ["*"] }
        ])
      rescue Microsandbox::CloudHttpError
        nil
      end
      JSON.parse(capture.value).dig("network", "secrets", "entries").each do |entry|
        puts [entry["env_var"], *entry["allowed_hosts"].map { |host| "\#{host["type"]}:\#{host["value"]}" }].join(" ")
      end
    RUBY
    lib = File.expand_path("../lib", __dir__)

    output = IO.popen([RbConfig.ruby, "-I", lib, "-e", script], &:read)

    assert_true $?.success?
    assert_equal [
      "GITHUB_TOKEN exact:github.com wildcard:*.githubusercontent.com",
      "API_KEY exact:api.example.com",
      "ANY_HOST_KEY any:"
    ], output.lines(chomp: true)
  end

  def test_secret_rejects_a_second_entry_for_the_same_env
    secrets = [
      { env: "GITHUB_TOKEN", value: "token", allowed_host: "github.com" },
      { env: "GITHUB_TOKEN", value: "token", allowed_host: "api.github.com" }
    ]

    error = assert_raise(ArgumentError) do
      Microsandbox::Sandbox.create("ruby-test", image: "alpine", secrets: secrets)
    end

    assert_equal 'secret "GITHUB_TOKEN": more than one entry uses this env; list all its hosts in :allowed_hosts',
                 error.message
  end

  def test_secret_allowed_hosts_shapes_are_validated
    cases = {
      { allowed_host: "a.example.com", allowed_hosts: ["b.example.com"] } =>
        [ArgumentError, 'secret "API_KEY": :allowed_host and :allowed_hosts are mutually exclusive; set one'],
      {} => [ArgumentError, "missing keyword: :allowed_hosts"],
      { allowed_hosts: [] } =>
        [ArgumentError, 'secret "API_KEY": requires at least one allowed host or allowed host pattern'],
      { allowed_hosts: "api.example.com" } => [TypeError, "allowed_hosts must be an Array"],
      { allowed_hosts: ["api.example.com", 1] } => [TypeError, "allowed_hosts must contain only Strings"]
    }

    cases.each do |hosts, (error_class, message)|
      error = assert_raise(error_class) do
        Microsandbox::Sandbox.create("ruby-test", image: "alpine", secrets: [{ env: "API_KEY", value: "v", **hosts }])
      end
      assert_equal message, error.message
    end
  end

  def test_create_accepts_proxy_keyword
    proxy = Microsandbox::OutboundProxy.socks5("not-an-address")

    error = assert_raise(Microsandbox::NetworkPolicyError) do
      Microsandbox::Sandbox.create("ruby-test", proxy: proxy)
    end

    assert_match(/invalid SOCKS5 proxy address/, error.message)
  end

  def test_create_applies_protocol_specific_proxy_authentication
    socks4 = Microsandbox::OutboundProxy.socks4("127.0.0.1:1080").user_id("")
    socks4_error = assert_raise(Microsandbox::NetworkPolicyError) do
      Microsandbox::Sandbox.create("ruby-test", proxy: socks4)
    end

    password = Microsandbox::SecretSource.env("SOCKS5_PASSWORD")
    socks5 = Microsandbox::OutboundProxy.socks5("127.0.0.1:1080").credentials("", password)
    socks5_error = assert_raise(Microsandbox::NetworkPolicyError) do
      Microsandbox::Sandbox.create("ruby-test", proxy: socks5)
    end

    assert_match(/invalid SOCKS4 user ID/, socks4_error.message)
    assert_match(/invalid SOCKS5 credentials/, socks5_error.message)
  end

  def test_unknown_create_keyword_is_rejected_before_runtime_start
    error = assert_raise(ArgumentError) do
      Microsandbox::Sandbox.create("ruby-test", unsupported_option: true)
    end

    assert_match(/unknown keyword/, error.message)
  end

  def test_ports_accepts_mapping_and_list_forms
    # Option parsing runs before name validation, so reaching the name error
    # means the ports parsed.
    [
      { 8080 => 80, 8443 => 443 },
      [
        { host_port: 8080, guest_port: 80 },
        { host_port: 8080, guest_port: 80, bind: "0.0.0.0", protocol: "tcp" },
        { host_port: 5353, guest_port: 53, bind: "::1", protocol: :udp }
      ]
    ].each do |ports|
      assert_raise(Microsandbox::InvalidConfigError) { Microsandbox::Sandbox.create("", ports: ports) }
    end
  end

  def test_ports_rejects_an_invalid_bind_address
    error = assert_raise(ArgumentError) do
      Microsandbox::Sandbox.create("ruby-test", ports: [{ host_port: 8080, guest_port: 80, bind: "localhost" }])
    end

    assert_equal "invalid bind address: localhost", error.message
  end

  def test_ports_rejects_an_invalid_protocol
    error = assert_raise(ArgumentError) do
      Microsandbox::Sandbox.create("ruby-test", ports: [{ host_port: 8080, guest_port: 80, protocol: "sctp" }])
    end

    assert_equal "invalid port protocol: sctp", error.message
  end

  def test_ports_rejects_an_unknown_entry_key
    error = assert_raise(ArgumentError) do
      Microsandbox::Sandbox.create("ruby-test", ports: [{ host_port: 8080, guest_port: 80, host: "0.0.0.0" }])
    end

    assert_equal "unknown keyword: :host", error.message
  end

  def test_ports_rejects_a_missing_port
    error = assert_raise(ArgumentError) do
      Microsandbox::Sandbox.create("ruby-test", ports: [{ host_port: 8080 }])
    end

    assert_equal "missing keyword: :guest_port", error.message
  end

  def test_ports_rejects_other_shapes
    assert_raise(ArgumentError) { Microsandbox::Sandbox.create("ruby-test", ports: "8080:80") }
    assert_raise(ArgumentError) { Microsandbox::Sandbox.create("ruby-test", ports: [[8080, 80]]) }
  end

  def test_invalid_sandbox_name_is_reported_as_sdk_error
    error = assert_raise(Microsandbox::InvalidConfigError) { Microsandbox::Sandbox.create("") }

    assert_kind_of Microsandbox::Error, error
    assert_equal "invalid-config", error.code
  end

  def test_invalid_network_host_raises_network_policy_error
    # The policy is built while parsing the create options, before any
    # runtime call, so a malformed hostname fails without a sandbox.
    error = assert_raise(Microsandbox::NetworkPolicyError) do
      Microsandbox::Sandbox.create("ruby-test", network: { allowed_hosts: ["not a host!"], allowed_ports: [443] })
    end

    assert_kind_of Microsandbox::Error, error
    assert_equal "network-policy-error", error.code
    assert_match(/not a host!/, error.message)
  end

  def test_network_rules_accept_every_destination_form
    # Policy parsing runs before name validation, so reaching the name error
    # means the policy built.
    [
      { rules: [] },
      { default_egress: :allow, default_ingress: "deny" },
      { rules: [*Microsandbox::Rule.allow_dns, { action: :allow, destination: "172.28.0.0/16" }] },
      {
        rules: [
          { action: "allow", destination: "*" },
          { action: :allow, destination: "10.0.0.5", protocol: :tcp, port: 4318 },
          { action: :allow, destination: "api.example.com", protocol: "tcp", port: "8000-9000" },
          { action: :allow, destination: ".github.com", port: 443 },
          { action: :allow, destination: "suffix=githubusercontent.com" },
          { action: :allow, destination: "domain=host.example.com" },
          { action: :deny, destination: "metadata" },
          { action: :deny, direction: :any, destination: :multicast },
          { action: :allow, direction: :ingress, destination: "loopback", protocol: :udp },
          { action: :allow, destination: Microsandbox::Destination.group("link-local"), protocol: :icmpv4 },
          { action: :allow, destination: Microsandbox::Destination.group(:link_local), protocol: :icmpv6 },
          Microsandbox::Rule.allow(destination: Microsandbox::Destination.any),
          Microsandbox::Rule.allow(destination: Microsandbox::Destination.ip("::1")),
          Microsandbox::Rule.allow(destination: Microsandbox::Destination.cidr("fd00::/8")),
          Microsandbox::Rule.allow(destination: Microsandbox::Destination.domain("example.com")),
          Microsandbox::Rule.allow(destination: Microsandbox::Destination.domain_suffix("example.org")),
          Microsandbox::Rule.deny(destination: Microsandbox::Destination.group(:private)),
          Microsandbox::Rule.allow(destination: { kind: "domain-suffix", value: "example.net" }),
          *Microsandbox::Rule.deny_dns
        ]
      }
    ].each do |network|
      assert_raise(Microsandbox::InvalidConfigError) { Microsandbox::Sandbox.create("", network: network) }
    end
  end

  def test_rule_factories_build_rule_hashes
    assert_equal(
      [
        { action: :allow, direction: :egress, destination: { kind: :group, value: :host }, protocol: :udp, port: 53 },
        { action: :allow, direction: :egress, destination: { kind: :group, value: :host }, protocol: :tcp, port: 53 }
      ],
      Microsandbox::Rule.allow_dns
    )
    assert_equal %i[deny deny], Microsandbox::Rule.deny_dns.map { |rule| rule[:action] }
    assert_equal(
      { action: :deny, direction: :ingress, destination: { kind: :cidr, value: "10.0.0.0/8" }, port: "80-90" },
      Microsandbox::Rule.deny(direction: :ingress, destination: Microsandbox::Destination.cidr("10.0.0.0/8"), port: "80-90")
    )
  end

  def test_network_rules_reject_invalid_values
    [
      [{ rules: [{ direction: :egress }] }, ArgumentError, "missing keyword: :action"],
      [{ rules: [{ action: :permit }] }, ArgumentError, "unknown rule action: permit"],
      [{ default_egress: :drop }, ArgumentError, "unknown default_egress: drop"],
      [{ default_ingress: "block" }, ArgumentError, "unknown default_ingress: block"],
      [{ rules: [{ action: :allow, direction: :sideways }] }, ArgumentError, "unknown direction: sideways"],
      [{ rules: [{ action: :allow, protocol: :sctp }] }, ArgumentError, "unknown protocol: sctp"],
      [{ rules: [{ action: :allow, port: "9000-8000" }] }, ArgumentError, "invalid port or port range: 9000-8000"],
      [{ rules: [{ action: :allow, port: "typo" }] }, ArgumentError, "invalid port or port range: typo"],
      [{ rules: [{ action: :allow, port: 70_000 }] }, ArgumentError, "invalid port or port range: 70000"],
      [{ rules: [{ action: :allow, port: 1.5 }] }, TypeError, "port must be an Integer or String"],
      [{ rules: [{ action: :allow, destination: { kind: :group, value: :lan } }] }, ArgumentError, "unknown destination group: lan"],
      [{ rules: [{ action: :allow, destination: { kind: :subnet, value: "x" } }] }, ArgumentError, "unknown destination kind: subnet"],
      [{ rules: [{ action: :allow, destination: { kind: :cidr } }] }, ArgumentError, "value is required for destination kind `cidr`"],
      [{ rules: [{ action: :allow, destination: 42 }] }, TypeError, "destination must be a String, Symbol, or Hash"],
      [{ rules: [{ action: :allow, dest: "x" }] }, ArgumentError, "unknown keyword: :dest"],
      [{ rules: "allow" }, ArgumentError, "rules must be an Array of Hashes"],
      [{ rules: ["allow"] }, ArgumentError, "rules entries must be Hashes"],
      [{ allowed_hosts: ["example.com"], allowed_ports: [443], rules: [] }, ArgumentError, "unknown keyword: :allowed_hosts"]
    ].each do |network, error_class, message|
      error = assert_raise(error_class) { Microsandbox::Sandbox.create("ruby-test", network: network) }
      assert_equal message, error.message
    end
  end

  def test_network_rule_destinations_are_validated_by_the_policy_builder
    [
      [[{ action: :allow, destination: "public" }, { action: :allow, destination: "10.0.0.0/33" }], "rule #1: invalid CIDR `10.0.0.0/33`"],
      [[{ action: :allow, destination: Microsandbox::Destination.ip("10.0.0.300") }], "rule #0: invalid IP address `10.0.0.300`"],
      [[{ action: :allow, destination: "suffix=com" }], "rule #0: invalid domain `com`"],
      [[{ action: :allow, direction: :ingress, protocol: :icmpv4 }], "rule #0"]
    ].each do |rules, message|
      error = assert_raise(Microsandbox::NetworkPolicyError) do
        Microsandbox::Sandbox.create("ruby-test", network: { rules: rules })
      end
      assert_include error.message, message
    end
  end

  def test_typed_error_is_rescued_by_base_error
    rescued = begin
      Microsandbox::Sandbox.create("")
    rescue Microsandbox::Error => error
      error
    end

    assert_instance_of Microsandbox::InvalidConfigError, rescued
  end

  def test_base_error_code
    assert_equal "microsandbox-error", Microsandbox::Error.code
    assert_equal "microsandbox-error", Microsandbox::Error.new("boom").code
  end

  def test_error_classes_are_direct_subclasses_of_error
    defined_classes = Microsandbox.constants.select do |name|
      constant = Microsandbox.const_get(name)
      constant.is_a?(Class) && constant < Microsandbox::Error
    end

    # JobError carries a code from the managed-job operation, while ERROR_CLASSES
    # contains the fixed-code errors checked by test_error_codes_are_unique_kebab_case.
    expected_classes = ERROR_CLASSES + [:JobError]
    assert_equal expected_classes.sort, defined_classes.sort
    expected_classes.each do |name|
      assert_equal Microsandbox::Error, Microsandbox.const_get(name).superclass, name
    end
  end

  def test_error_codes_are_unique_kebab_case
    codes = ERROR_CLASSES.map { |name| Microsandbox.const_get(name).code }

    codes.each { |code| assert_match(/\A[a-z]+(-[a-z]+)*\z/, code) }
    assert_equal codes, codes.uniq
    assert_not_include codes, Microsandbox::Error.code
    assert_equal "exec-timeout", Microsandbox::ExecTimeoutError.new("boom").code
  end

  def test_unsupported_error_attributes_default_to_nil
    error = Microsandbox::UnsupportedError.new("boom")

    assert_nil error.operation
    assert_nil error.hint
    assert_equal "unsupported", error.code
  end

  def test_snapshot_source_recovery_error_attributes_default_to_nil
    error = Microsandbox::SnapshotSourceRecoveryError.new("boom")

    %i[source_sandbox checkpoint_id checkpoint_root checkpoint_path artifact detail publication_error].each do |name|
      assert_nil error.public_send(name), name
    end
    assert_equal "snapshot-source-recovery", error.code
  end

  def test_missing_sandbox_raises_sandbox_not_found_error
    # The local backend answers from its catalog without booting a VM.
    name = "does-not-exist-#{Process.pid}-#{rand(1_000_000)}"

    error = assert_raise(Microsandbox::SandboxNotFoundError) { Microsandbox::Sandbox.get(name) }

    assert_kind_of Microsandbox::Error, error
    assert_equal "sandbox-not-found", error.code
  end

  def test_unsupported_error_carries_operation_and_hint
    # The cloud backend rejects `replace:` while building the request, before
    # any network access, so this needs neither credentials nor connectivity.
    # Selecting a backend is process-global, so the probe runs in a separate
    # Ruby process and this process keeps its backend selection. A fork would
    # not do: on macOS the cloud client initializes Foundation classes on
    # first use, which the Objective-C runtime refuses in a forked child.
    backend_kind = Microsandbox.default_backend_kind
    script = <<~RUBY
      require "microsandbox"
      Microsandbox.use_cloud_backend!("test-key", url: "http://127.0.0.1:9")
      begin
        Microsandbox::Sandbox.create("ruby-test", image: "alpine", replace: true)
        puts "no error raised"
      rescue Microsandbox::UnsupportedError => error
        puts error.message, error.operation, error.hint
      end
    RUBY
    lib = File.expand_path("../lib", __dir__)

    output = IO.popen([RbConfig.ruby, "-I", lib, "-e", script], &:read)

    assert_true $?.success?
    assert_equal [
      "sandbox.create is not supported by this backend: the replace option is not accepted here",
      "sandbox.create",
      "the replace option is not accepted here"
    ], output.lines(chomp: true)
    assert_equal backend_kind, Microsandbox.default_backend_kind
  end

  def test_http_deny_message_reaches_cloud_validation
    script = <<~RUBY
      require "microsandbox"
      Microsandbox.use_cloud_backend!("test-key", url: "http://127.0.0.1:9")
      settings = Microsandbox::HttpBuilder.new
      settings.deny_message("dormant")
      abort "message enabled responses" unless settings.response.nil?
      settings.deny_response(true).deny_response(false)
      abort "disable ignored" unless settings.response == false
      operations = [
        -> { Microsandbox::Sandbox.create("ruby-test", image: "alpine", http: { deny_response: true }) },
        -> { Microsandbox::Sandbox.builder("ruby-test").image("alpine").http { |h| h.deny_response(true).deny_message("blocked {host}") }.create }
      ]
      operations.each do |operation|
        begin
          operation.call
          abort "expected cloud to reject the local-only option"
        rescue Microsandbox::UnsupportedError => error
          abort error.message unless error.message.include?("network.http.deny_response")
          puts "rejected"
        end
      end
    RUBY
    lib = File.expand_path("../lib", __dir__)
    output = IO.popen([RbConfig.ruby, "-I", lib, "-e", script], &:read)

    assert_true $?.success?
    assert_equal ["rejected", "rejected"], output.lines(chomp: true)
  end

  def test_with_is_available
    assert_respond_to Microsandbox::Sandbox, :with
  end

  def test_explicit_stop_timeout_requires_one_argument_on_both_receivers
    [Microsandbox::Sandbox, Microsandbox::SandboxHandle].each do |receiver|
      assert_equal 1, receiver.instance_method(:stop_with_timeout).arity
      assert_equal(-1, receiver.instance_method(:stop).arity)
    end
  end

  def test_connect_or_create_is_available
    assert_respond_to Microsandbox::Sandbox, :connect_or_create
    assert_respond_to Microsandbox::Sandbox.builder("ruby-test"), :connect_or_create
  end

  def test_entrypoint_rejects_non_string_elements
    builder = Microsandbox::Sandbox.builder("ruby-test")
    assert_raise(TypeError) { builder.entrypoint(["sh", 1]) }
  end

  def test_with_preserves_block_error_when_stop_also_fails
    fake = Object.new
    fake.define_singleton_method(:stop) { raise "stop failed" }
    sandbox_class = Class.new(Microsandbox::Sandbox)
    sandbox_class.define_singleton_method(:create) { |*, **| fake }

    error = assert_raise(ArgumentError) do
      sandbox_class.with("ruby-test") { raise ArgumentError, "block failed" }
    end

    assert_equal "block failed", error.message
  end

  def test_with_raises_stop_error_after_successful_block
    fake = Object.new
    fake.define_singleton_method(:stop) { raise "stop failed" }
    sandbox_class = Class.new(Microsandbox::Sandbox)
    sandbox_class.define_singleton_method(:create) { |*, **| fake }

    error = assert_raise(RuntimeError) do
      sandbox_class.with("ruby-test") { :ok }
    end

    assert_equal "stop failed", error.message
  end

  def test_native_runtime_rebuilds_after_fork
    omit("fork is unavailable") unless Process.respond_to?(:fork)

    Microsandbox::Sandbox.list(limit: 1)
    reader, writer = IO.pipe
    child = fork do
      reader.close
      begin
        Microsandbox::Sandbox.list(limit: 1)
        writer.write("ok")
      rescue StandardError => error
        writer.write("#{error.class}: #{error.message}")
      ensure
        writer.close
        exit! 0
      end
    end
    writer.close

    result = Timeout.timeout(10) { reader.read }
    Process.wait(child)

    assert_equal "ok", result
  ensure
    reader&.close
    writer&.close
    if child
      begin
        Process.kill("KILL", child)
        Process.wait(child)
      rescue Errno::ESRCH, Errno::ECHILD
        nil
      end
    end
  end
end
