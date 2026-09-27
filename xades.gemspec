# frozen_string_literal: true

require_relative "lib/xades/version"

Gem::Specification.new do |spec|
  spec.name = "xades"
  spec.version = Xades::VERSION
  spec.authors = ["Chris Hasinski"]
  spec.email = ["krzysztof.hasinski@gmail.com"]

  spec.summary = "XAdES-BES/BASELINE-B XML signing and verification (ETSI EN 319 132) for pure Ruby."
  spec.description = "Sign and verify XML documents with XAdES-BES / BASELINE-B advanced electronic " \
                      "signatures (ETSI EN 319 132), the profile used for eIDAS-adjacent flows such as " \
                      "Poland's KSeF e-invoicing authentication. Pure MRI: Nokogiri for XML/C14N, " \
                      "OpenSSL for RSA/ECDSA."
  spec.homepage = "https://github.com/khasinski/xades"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore .rspec spec/ .github/ .rubocop.yml])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "base64"
  spec.add_dependency "nokogiri", "~> 1.15"

  # For more information and examples about making a new gem, check out our
  # guide at: https://guides.rubygems.org/make-your-own-gem/
end
