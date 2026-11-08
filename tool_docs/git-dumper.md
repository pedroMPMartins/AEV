# git-dumper

git-dumper is a tool used to dump and reconstruct a Git repository from an HTTP web server that accidentally has its `.git` directory publicly accessible.

Even if directory listing is disabled on the server, git-dumper can fetch files like `.git/HEAD`, `.git/index`, object files, and packed refs to rebuild the entire repository locally, including commit history, branches, and previous versions of files.


## Installation

On modern Linux systems (like Ubuntu and Debian), `pip` usually prevents installing packages globally due to externally managed environments (PEP 668). The recommended way to install and run it is through `pipx`:

```bash
sudo apt update && sudo apt install pipx
pipx install git-dumper
```


## Dumping a repository

To dump a repository, provide the target URL hosting the website (or `.git` endpoint) and the local destination folder where the dumped repository should be stored:

```bash
pipx run git-dumper <URL> <destination_folder>
```

For example, on the challenge at `http://10.110.3.72:8013/`:

```bash
pipx run git-dumper http://10.110.3.72:8013/ recovered_repo
```

This downloads all available Git objects and reconstructs the working tree in `recovered_repo/`.


## Inspecting the recovered repository

Once the repository is downloaded, navigate into the directory and use standard `git` commands to explore the commit history:

```bash
cd recovered_repo
git log --all --oneline
```

In the Port 8013 challenge, this was the output:
```
s12@s12:~/recovered_repo$ git log --all --oneline
eea9eb5 (HEAD -> master) chore: remove temp flag
e187934 temp: add flag flag{g1t_h1story_l34ks} for testing
```

As seen in the log, a previous commit (`e187934`) added a flag that was later removed in `eea9eb5`. The commit message itself leaked the flag, but you can also inspect the changes introduced in that commit using:

```bash
git show e187934
```

Or view the difference between commits:
```bash
git diff eea9eb5 e187934
```
