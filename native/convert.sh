#!/bin/sh
cat main.c | perl -ne '$content.=$_;END{$content=~s|(JNIEXPORT [^\n]+?)\n\s+?(\([^\)]+?\));|$1$2 {\n  return 0;\n}\n|sg; print $content}' > main2.c

