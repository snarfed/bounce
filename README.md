<img src="..." width="120" /> [Bounce](https://bounce.anew.social/) [![Circle CI](https://circleci.com/gh/snarfed/bounce.svg?style=svg)](https://circleci.com/gh/snarfed/bounce)
===

_Switch platforms, keep your people_

Bounce lets you migrate from one social network to another and keep all of your followers. It currently supports [Mastodon](https://joinmastodon.org), [Pixelfed](https://pixelfed.org/), [Bluesky](https://bsky.social/), and [micro.blog](https://micro.blog/)

https://bounce.anew.social/

License: This project is placed in the public domain. You may also use it under the [CC0 License](https://creativecommons.org/publicdomain/zero/1.0/).


Development
---
Pull requests are welcome! First, fork and clone this repo. Then, install the [Google Cloud SDK](https://cloud.google.com/sdk/) and run `gcloud components install cloud-firestore-emulator` to install the [Firestore emulator](https://cloud.google.com/firestore/docs/emulator). Once you have them, set up your environment by running these commands in the repo root directory:


```sh
gcloud config set project bounce-migrate
python3 -m venv local
source local/bin/activate
pip install -r requirements.txt
```

Now, run the tests to check that everything is set up ok:

```shell
gcloud emulators firestore start --host-port=:8089 --database-mode=datastore-mode < /dev/null >& /dev/null &
python3 -m unittest discover
```

Finally, run this in the repo root directory to start the web app locally:

```shell
GAE_ENV=localdev FLASK_ENV=development flask run -p 8080
```

If you send a pull request, please include (or update) a test for the new functionality!

If you hit an error during setup, check out the [oauth-dropins Troubleshooting/FAQ section](https://github.com/snarfed/oauth-dropins#troubleshootingfaq).

You may need to change [granary](https://github.com/snarfed/granary), [oauth-dropins](https://github.com/snarfed/oauth-dropins), [mf2util](https://github.com/kylewm/mf2util), or other dependencies as well as as Bounce. To do that, clone their repo locally, then install them in "source" mode with e.g.:

```sh
pip uninstall -y granary
pip install -e <path to granary>
```

To deploy to the production instance on App Engine - if @snarfed has added you as an owner - run:

```sh
gcloud -q beta app deploy --no-cache --project bounce-migrate *.yaml
```
