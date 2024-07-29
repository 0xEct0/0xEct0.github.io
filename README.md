# Blog

View the blog here [https://0xect0.github.io/](https://0xect0.github.io/).

> [!WARNING]
> When adding code blocks with multiple curly braces within it. In Liquid (the templating engine used by Jekyll), curly braces `{{ }}` are used to denote variables or expressions that should be processed. When these braces appear in the content, Liquid tries to interpret them, which leads to syntax errors if they're part of a code block rather than a Liquid template. To fix - escape these curly braces by using the raw tag in Jekyll, which tells Liquid to ignore the content inside these tags. Modify post to wrap the code block within `{% raw %}` and `{% endraw %}` tags.