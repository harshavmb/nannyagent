---
sidebar_position: 2
---

# Writing Documentation

This guide covers how to write documentation for NannyAgent using Docusaurus.

## Markdown Basics

Docusaurus uses [Markdown](https://www.markdownguide.org/basic-syntax/) for content. Here are some basics:

### Headings

```markdown
# Heading 1
## Heading 2
### Heading 3
```

### Text Formatting

```markdown
*This text will be italic*
_This will also be italic_

**This text will be bold**
__This will also be bold__

~~This text will be strikethrough~~
```

### Lists

**Ordered List:**
```markdown
1. First item
2. Second item
3. Third item
```

**Unordered List:**
```markdown
- First item
- Second item
- Third item
```

## Docusaurus Features

Docusaurus adds extra features on top of standard Markdown.

### Front Matter

The top of each Markdown file should contain front matter to configure the page.

```yaml
---
title: My Custom Title
sidebar_position: 1
---
```

- `title`: Sets the title of the page.
- `sidebar_position`: Specifies the order of the page in the sidebar.

### Admonitions

Admonitions are a great way to highlight important information.

```markdown
:::note

This is a note.

:::

:::tip

This is a tip.

:::

:::info

This is some information.

:::

:::warning

This is a warning.

:::

:::danger

This is a dangerous warning.

:::
```

### Code Blocks

You can add code blocks with syntax highlighting.

````markdown
```go
package main

import "fmt"

func main() {
  fmt.Println("Hello, World!")
}
```
````

### Tabs

You can create tabbed content to show different information in a single block.

````markdown
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="go" label="Go">

  ```go
  package main
  
  import "fmt"
  
  func main() {
    fmt.Println("Hello, Go!")
  }
  ```

  </TabItem>
  <TabItem value="js" label="JavaScript">

  ```javascript
  console.log('Hello, JavaScript!');
  ```

  </TabItem>
</Tabs>
````

### Linking to Other Documents

You can link to other documents by using their file path relative to the current file.

```markdown
[Link to Configuration](./CONFIGURATION.md)
```

### Embedding Images

Place images in the `static/img` directory and you can embed them like this:

```markdown
![Docusaurus Logo](/img/logo.svg)
```
