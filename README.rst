travis-auto-rebuilder
=====================

Have you been tired of repetitious failure-and-retries?  Yes, you're aware that
you should properly fix the build so that it's deterministic, but you don't want
to fight with them, right?

Here's an evil tool to make your ad-hoc habit run long.  It's a simple webhook
receiver for Travis CI to rebound failed builds.


How to use
----------

TL;DR: Make a new webhook receiver and then edit your .travis.yml configuration
to notify the receiver when a build fails.

Creating a new receiver
~~~~~~~~~~~~~~~~~~~~~~~

You can create a new receiver from the website:

https://travis-auto-rebuilder.herokuapp.com/

It shows you a form which takes two three fields: **repo slug**, **token**,
and **max retries**.

**Repo slug** means ``foo/bar`` from ``https://github.com/foo/bar``, and
you can find your **token** through ``travis token`` command (if you haven't
used it before, you need to install it and login:
``gem install travis && travis login``).

**Max retries** means what it says.  It's disallowed to be greater than 5.

There are two optional fields as well: **job numbers** and **subject to**.

**Job numbers**: If you want a receiver to
be sensitive to only some jobs and ignore other jobs, fill this field with
comma-separated numbers.  Each number means an index number appeared after a
period from a job number, e.g., 4 from 123.4 (where 123 is a build number).
Suppose if you've filled it with ``1,2``, then it won't automatically restart
a build (suppose its number is 123) unless its job 123.1 or 123.2 fails.
Leave this empty if you want every build to be automatically restarted
when any job in the build fails.

**Subject to**: If particular jobs are obviously deterministic so that we can
ensure that the whole build shouldn't be automatically retried when these
deterministic jobs fail, fill this field with the these deterministic job
numbers.  The format is the same to the **job numbers** field.

Fill the form and then click the submit button.  It will show a url of
the new webhook receiver you've just made.


Configuring .travis.yml
~~~~~~~~~~~~~~~~~~~~~~~

Travis CI provides built-in webhooks_ and it's called build notifications.
See the below example:

.. code-block:: yaml

   notifications:
     webhooks:
       urls:
       - https://travis-auto-rebuilder.herokuapp.com/.../
       # ^-- Your receiver url goes here.
       on_failure: always
       on_success: never
       on_start: never

Note that it specify to be notified when a build fails: ``on_failure: always``.

.. _webhooks: https://docs.travis-ci.com/user/notifications/#Configuring-webhook-notifications
