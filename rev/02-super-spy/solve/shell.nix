with import <nixpkgs> {};
let
  shellPythonPackages = python-packages: [
    python-packages.pip
  ];
  shellPython = python37.withPackages shellPythonPackages;
in
pkgs.mkShell {
  buildInputs = [
    shellPython
  ];
  shellHook = ''
      export PIP_PREFIX="$(pwd)/_build/pip_packages"
      export PYTHONPATH="$(pwd)/_build/pip_packages/lib/python3.7/site-packages:$PYTHONPATH" 
      unset SOURCE_DATE_EPOCH
  '';
}
