# typed: false
# frozen_string_literal: true

class Supplychain < Formula
  desc "Supply-chain scanner for JS projects (manifest + lockfile + IOCs + OSV)"
  homepage "https://github.com/noeljackson/supplychain"
  version "0.1.2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/noeljackson/supplychain/releases/download/v#{version}/supplychain-darwin-arm64"
      sha256 "8167be99b1e6ebec016d96dbbc940cbb63b95404b352d22da90be0b56c83c0ed"
    else
      url "https://github.com/noeljackson/supplychain/releases/download/v#{version}/supplychain-darwin-amd64"
      sha256 "0e103a11f608a0f762d1b01ed2064e231bd0707dbdedd230d31f19e0e681f2d2"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/noeljackson/supplychain/releases/download/v#{version}/supplychain-linux-arm64"
      sha256 "6e1af37af8e495a25f6aa16c020f28a4f9de3e4a6ac09948a6725eb6febe6afe"
    else
      url "https://github.com/noeljackson/supplychain/releases/download/v#{version}/supplychain-linux-amd64"
      sha256 "567467bdf2ad7e29b1602f740df676da175c58d827ade870e2968ace60aafe53"
    end
  end

  def install
    # The release asset is the raw binary; rename to "supplychain" on install.
    bin.install Dir["*"].first => "supplychain"
  end

  test do
    assert_match(/supplychain v?\d+\.\d+\.\d+/, shell_output("#{bin}/supplychain version"))
  end
end
