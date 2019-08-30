#!/usr/bin/env elixir

IO.puts "<!-- AUTOMATICALLY GENERATED DO NOT EDIT -->"
IO.puts ""

Path.join(__DIR__, "libforks.h")
|> File.read!
|> String.split("\n")
|> Enum.reject(fn l -> String.ends_with?(l, "// no doc") end)
|> Enum.chunk_while(
  {:code, ""},
  fn line, {state, acc} ->
    if String.starts_with?(line, "//") do
      comment = String.trim(String.slice(line, 2, String.length(line)))
      case state do
        :comment -> {:cont, {:comment, acc <> "\n" <> comment}}
        :code -> {:cont, {state, acc}, {:comment, comment}}
      end
    else
      case state do
        :comment -> {:cont, {state, acc}, {:code, line}}
        :code -> {:cont, {:code, acc <> "\n" <> line}}
      end
    end
  end,
  fn {state, acc} ->
    {:cont, {state, acc}}
  end
)
|> Enum.map(fn {kind, text} -> {kind, String.trim(text)} end)
|> Enum.filter(fn {_kind, text} -> text !== "" end)
|> Enum.map(
  fn
    {:code, text} -> "```c\n" <> text <> "\n```\n"
    {:comment, text} -> text <> "\n"
  end
)
|> Enum.join("\n")
|> IO.puts()

