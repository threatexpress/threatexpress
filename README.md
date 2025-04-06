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

**Reference**

- https://www.mkdocs.org/user-guide/deploying-your-docs/

---

## Mkdocs

This wiki use mkdocs and the mkdocs-material theme

MkDocs is a static site generator that's geared towards building project documentation. Documentation source files are written in Markdown, and configured with a single YAML configuration file.

- https://www.mkdocs.org
- https://squidfunk.github.io/mkdocs-material/

---

## Font Awesome

Reference: http://bwmarrin.github.io/MkDocsPlus/fontawesome/

## Requirements and Setup

Note: This has been tested with python 3.12 running on MacOS in venv

**Requirements**

```
pip install mkdocs-material
pip install mkdocs
```

## References

- Material Theme Documentation and Reference: http://mkdocs.github.io/mkdocs-bootswatch/#installation-usage

---

## Directory and File Info

- `./docs/` : mkdocs content
- `./docs/img/` : Store all course images here
- `mkdocs.yml` : mkdocs configuration file
- `./site/` : Prod version of site. Not tracked in git. Used for testing or manual deployment
