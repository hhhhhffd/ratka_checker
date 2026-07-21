#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

for fixture_dir in "$root"/*; do
    [ -d "$fixture_dir/src" ] || continue
    name=$(basename "$fixture_dir")
    classes="$build_dir/$name/classes"
    mkdir -p "$classes"
    javac --release 21 -d "$classes" $(find "$fixture_dir/src" -name '*.java' -print)
    printf '%s' '{"schemaVersion":1,"id":"compiledfixture","entrypoints":{"main":["example.Fixture"]}}' \
        > "$classes/fabric.mod.json"
    jar --create --file "$fixture_dir/fixture.jar" -C "$classes" .
done

nested="$root/nested_malicious"
nested_classes="$build_dir/nested/classes"
mkdir -p "$nested_classes"
javac --release 21 -d "$nested_classes" $(find "$nested/src" -name '*.java' -print)
jar --create --file "$build_dir/nested-payload.jar" -C "$nested_classes" .
mkdir -p "$build_dir/nested-root"
printf '%s' '{"schemaVersion":1,"id":"nestedfixture","entrypoints":{"main":["example.Fixture"]}}' \
    > "$build_dir/nested-root/fabric.mod.json"
mkdir -p "$build_dir/nested-root/META-INF/jars"
cp "$build_dir/nested-payload.jar" "$build_dir/nested-root/META-INF/jars/nested-payload.jar"
jar --create --file "$nested/fixture.jar" -C "$build_dir/nested-root" .
