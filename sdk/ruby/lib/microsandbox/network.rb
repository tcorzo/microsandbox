# frozen_string_literal: true

module Microsandbox
  # Typed destinations for `network: { rules: [...] }` entries. A plain String
  # destination is parsed as shorthand instead; these never are.
  module Destination
    def self.any = { kind: :any }
    def self.ip(ip) = { kind: :ip, value: ip }
    def self.cidr(cidr) = { kind: :cidr, value: cidr }
    def self.domain(domain) = { kind: :domain, value: domain }
    def self.domain_suffix(suffix) = { kind: :domain_suffix, value: suffix }
    def self.group(group) = { kind: :group, value: group }
  end

  # Rule hashes for `network: { rules: [...] }`.
  module Rule
    def self.allow(direction: :egress, protocol: nil, port: nil, destination: nil)
      { action: :allow, direction:, destination:, protocol:, port: }.compact
    end

    def self.deny(direction: :egress, protocol: nil, port: nil, destination: nil)
      { action: :deny, direction:, destination:, protocol:, port: }.compact
    end

    # Plain DNS (UDP/53 and TCP/53) to the sandbox gateway, as one rule per
    # protocol. DoT (TCP/853) is not included.
    def self.allow_dns
      %i[udp tcp].map { |protocol| allow(destination: Destination.group(:host), protocol:, port: 53) }
    end

    def self.deny_dns
      allow_dns.map { |rule| rule.merge(action: :deny) }
    end
  end
end
