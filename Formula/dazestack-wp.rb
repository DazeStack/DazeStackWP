class DazestackWp < Formula
  desc "Production-ready automated WordPress LEMP platform for Ubuntu"
  homepage "https://github.com/DazeStack/DazeStackWP"
  url "https://github.com/DazeStack/DazeStackWP/archive/refs/tags/v0.1.2.tar.gz"
  license "AGPL-3.0-or-later"

  depends_on "bash"

  def install
    bin.install "dazestack-wp.sh" => "dazestack-wp"
  end

  test do
    system "#{bin}/dazestack-wp", "--help"
  end
end
