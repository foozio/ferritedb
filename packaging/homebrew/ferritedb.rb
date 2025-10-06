class Ferritedb < Formula
  desc "Developer-friendly backend service in a single binary"
  homepage "https://ferritedb.dev"
  url "https://github.com/foozio/ferritedb/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed"
  license "MIT"
  head "https://github.com/foozio/ferritedb.git", branch: "main"

  depends_on "rust" => :build

  def install
    ENV["SQLX_OFFLINE"] = "true"
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "FerriteDB", shell_output("#{bin}/ferritedb --help")
  end
end
