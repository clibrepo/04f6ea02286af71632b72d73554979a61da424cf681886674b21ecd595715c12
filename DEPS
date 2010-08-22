vars = {
}

deps = {
  "external/src/gtest":
    "http://googletest.googlecode.com/svn/trunk@408",

  "external/src/protobuf/src":
    "http://protobuf.googlecode.com/svn/trunk@327",

  "external/tools/gyp":
    "http://gyp.googlecode.com/svn/trunk@837",

  "external/src/v8":
    "http://v8.googlecode.com/svn/trunk@5110",

	"external/src/boost":
		"http://svn.boost.org/svn/boost/trunk",

  "external/src/apr":
		"http://svn.apache.org/repos/asf/apr/apr/trunk",

	"external/src/curl":
		"git://github.com/bagder/curl.git",

	"external/src/transmission":
		"http://github.com/wereHamster/transmission.git",


	"external/src/cryptopp":
		"https://cryptopp.svn.sourceforge.net/svnroot/cryptopp",

	"external/src/zxing":
		"http://zxing.googlecode.com/svn/trunk",



}


deps_os = {
  "win": {

  },
  "mac": {
  },
  "unix": {
  },
}


include_rules = [
]


# checkdeps.py shouldn't check include paths for files in these dirs:
skip_child_includes = [
]


hooks = [
  {
    "pattern": ".",
    "action": ["python", "--version"],
  },
]
