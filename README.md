<img src="https://raw.github.com/snarfed/bounce/main/static/logomark-light-mode.svg" width="120" /> [Bounce](https://bounce.anew.social/)  
[![Circle CI](https://circleci.com/gh/snarfed/bounce.svg?style=svg)](https://circleci.com/gh/snarfed/bounce)
===

_Switch platforms, keep your people_

Bounce lets you migrate from one social network to another and keep all of your followers. It currently supports [Mastodon](https://joinmastodon.org) and [Bluesky](https://bsky.social/). We hope to add support for [Pixelfed](https://pixelfed.org/), [Threads](https://www.threads.net/), [micro.blog](https://micro.blog/), and more soon.

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


Sharing Bridgy Fed's memcache
---
Bounce modifies data in Bridgy Fed's datastore directly, but right now it can't access Bridgy Fed's MemoryStore memcache instance. It'd be a huge help if it could! That would let it [use memcache for ATProto sequence allocation](https://github.com/snarfed/arroba/issues/69) directly, and also share Bridgy Fed's ndb memcache caching natively, without having to hit Bridgy Fed's `/admin/memcache-evict` endpoint to manually evict stale cached datastore entities.

Theoretically, it _should_ be possible to set Bounce up to access Bridgy Fed's memcache with [Shared VPC](https://docs.cloud.google.com/vpc/docs/shared-vpc). I spent a lot of time trying to get that to work, but never succeeded. Grr. Here's what I did:

* Set up a Shared VPC on `bridgy-federated` as the host project, for its `default` VPC` and `bounce-migrate` as the service project.
* Added a `shared-serverless-vpc-connector-bounce` subnet to `bridgy-federated`'s VPC with IP range `10.9.0.0/28`.
* Added a [Serverless VPC Access connector](https://cloud.google.com/vpc/docs/serverless-vpc-access) `to-bridgy-fed-shared` to `bounce-migrate` on that subnet.
* Added this to Bounce's `app.yaml`:
  ```
  vpc_access_connector:
    name: projects/bounce-migrate/locations/us-central1/connectors/to-bridgy-fed-shared
  ```
* Redeployed Bounce.

That didn't work. Bounce couldn't connect to Bridgy Fed's memcache, and it also couldn't connect to Google APIs, eg for log collection. I tried a few more things, redeploying (if necessary) and testing after each one:

* Added lots of IAM roles, eg _Serverless VPC Access User_, _Compute Network User_ on Bounce's GAE service account *in the `bridgy-federated` project*, and many others
* Turned on _Private Google Access_ in the `shared-serverless-vpc-connector-bounce` subnet in `bridgy-federated`.
* Added `egress_setting: all-traffic` to `vpc_access_connector` in `app.yaml`.
  * ...and then had to [add a custom DNS zone for `googleapis.com.` in `bridgy-federated`](https://docs.cloud.google.com/vpc/docs/configure-private-google-access#config-domain) to allow network traffic to Google APIs. (Started to feel like uncomfortable unnecessary yak shaving at this point.)

At this point, Bounce _still_ couldn't connect to Bridgy Fed's memcache. It was connecting to most Google APIs, but still couldn't send logs to `199.36.153.*`. I could log to `stderr` and get those collected and visible in Log Explorer, but not Python logs via `google.cloud.logging.Client`.

I removed `egress_setting: all-traffic` from `app.yaml` and redeployed, confirmed in the web console that it reverted to the default `private-ip-ranges` value, and it _still_ couldn't connect to `199.36.153.*` to send logs. Wtf?! It was now worse off than when I'd started. So, I reverted it all. Grr.

(I talked through a lot of this with [Gemini Cloud Assist](https://console.cloud.google.com/gemini?project=bridgy-federated). It seemed helpful, but didn't actually get anything working.)
