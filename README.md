# Threatexpress Blog

---
## Quickstart

This blog is written in markdown and uses mkdocs to generate the HTML hosted using Git Pages on github

**Workflow**

- Create new content
- Push content 

```
git add .
git commit -a -m "new stuff"
git push
```

- Push to Git Pages

```
mkdocs gh-deploy
```

---
## Mkdocs

This wiki use mkdocs and the mkdocs-material theme

MkDocs is a static site generator that's geared towards building project documentation. Documentation source files are written in Markdown, and configured with a single YAML configuration file.

- https://www.mkdocs.org
- https://squidfunk.github.io/mkdocs-material/

## Requirements and Setup

Note: This has been tested with python 3.6 running on MacOS.

__Requirements__

```
pip3.6 install mkdocs
pip3.6 install mkdocs-material
pip3.6 install pygments
pip3.6 install pymdown-extensions
```


## References

- Material Theme Documentation and Reference: http://mkdocs.github.io/mkdocs-bootswatch/#installation-usage
- https://squidfunk.github.io/mkdocs-material/getting-started/
- https://facelessuser.github.io/pymdown-extensions/

---
## Directory and File Info

- `./docs/` : mkdocs content
- `./docs/img/` : Store all course images here
- `mkdocs.yml` : mkdocs configuration file
- `./site/` : Prod version of site. Not tracked in git. Used for testing or manual deployment

