# -*- coding: utf-8 -*-

import functools
import logging
import os
import random

from apscheduler.triggers import cron
import munch
from oslo_utils import reflection
from oslo_utils import strutils
from six.moves import range as compat_range

from voluptuous import ALLOW_EXTRA

from voluptuous import All
from voluptuous import Length
from voluptuous import Optional
from voluptuous import Range
from voluptuous import Required
from voluptuous import Schema

from padre import ansible_utils
from padre import authorizers as auth
from padre import channel as c
from padre import exceptions as excp
from padre import followers
from padre import handler
from padre import handler_utils as hu
from padre import matchers
from padre import message as m
from padre import mixins
from padre import periodic_utils as peu
from padre import process_utils as pu
from padre import schema_utils as scu
from padre import slack_utils as su
from padre import trigger
from padre import utils


LOG = logging.getLogger(__name__)
LAUNCH_LINES = tuple([
    "Launching missiles...",
    "Compiling worlds...",
    "Hold on to your butts...",
    "Locating the required gigapixels...",
    "Spinning up the hamster...",
    "Shovelling coal into the server...",
    "Programming the flux capacitor...",
    "Bits are breeding...",
    "Enjoy the elevator music...",
    "Checking gravitational constant...",
    "At least you're not on hold...",
    "We're testing your patience...",
    "Following the white rabbit...",
    "Satellite moving into position...",
    "The bits are flowing slowly today...",
    "Loading humorous message...",
    "Last time the monkey didn't survive...",
    "Testing data on Timmy...",
    "Warming up the processors...",
    "Doing something useful...",
    "Prepare for awesomeness!...",
    "Counting backwards from infinity..",
    "Don't panic...",
])


def _find_retry_path(tmp_dir, playbook_path):
    # According to docs it should end up right by the playbook file?
    #
    # But just-incase, we will search a few locations...
    play_base, _play_ext = os.path.splitext(os.path.basename(playbook_path))
    play_dir = os.path.dirname(playbook_path)
    maybe_locs = [
        os.path.join(play_dir, ".retry"),
        os.path.join(play_dir, "%s.retry" % play_base),
        os.path.join(tmp_dir, ".retry"),
        os.path.join(tmp_dir, "%s.retry" % play_base),
    ]
    tried_locs = set()
    for p in maybe_locs:
        if p in tried_locs:
            continue
        tried_locs.add(p)
        if os.path.isfile(p):
            return p
    return None


def _extract_retry_hosts(tmp_dir, playbook_path):
    retry_hosts = set()
    retry_path = _find_retry_path(tmp_dir, playbook_path)
    if retry_path:
        with open(retry_path, 'rb') as fh:
            for line in fh:
                line = line.strip()
                if line:
                    retry_hosts.add(line)
    return retry_hosts, retry_path


def _setup_vault_pass(vault_pass, tmp_dir):
    vault_path = os.path.join(tmp_dir, 'vault-pass.txt')
    with open(vault_path, 'w') as vault_file:
        os.chmod(vault_path, 0o600)
        vault_file.write(vault_pass)
    return vault_path


def generate_cloud_inventories(config):
    inventories = {}
    try:
        fetch_func = config.plugins.env_fetcher_func
    except AttributeError:
        fetch_func = None
    if fetch_func:
        fetch_func = utils.import_func(fetch_func)
        cloud_envs = fetch_func(env_dir=config.get("env_dir"))
        for env, topo_fn in cloud_envs:
            tmp_env = "cloud-%s" % env.replace("_", "-")
            run_env = utils.get_environ()
            run_env.update({
                'ENV_TO_TARGET': env,
                'ANSIBLE_ENV': topo_fn,
            })
            inventories[tmp_env] = {
                'kind': 'static',
                'env': run_env,
                'env_real_name': env,
                'vault_pass_env': 'DEPLOY_PASS',
            }
    return inventories


def generate_kolla_ansible_extra_vars(working_dir,
                                      playbook_deps, vault_path=None):
    evs = {
        'working_dir': working_dir,
        'kolla_ansible_src_dir': playbook_deps['kolla-ansible'],
        'requirements_src_dir': playbook_deps['requirements'],
        'tempest_src_dir': playbook_deps['tempest'],
        'os_deploy_src_dir': playbook_deps['openstack-deploy'],
        'os_patches_src_dir': playbook_deps.get('openstack-patches'),
        'ply_src_dir': playbook_deps.get('ply'),
    }
    if vault_path:
        evs['os_deploy_secrets_path'] = vault_path
    return evs


class PlaybookHandler(mixins.AnsibleRunner, handler.TriggeredHandler):
    """
    Runs simple playbooks in a simple manner with a few simple options simply.
    """  # noqa

    handles_what = {
        # These are filled in during setup class time.
        'inventories': {},
        'playbooks': {},
        'message_matcher': matchers.match_or(
            matchers.match_slack("message"),
            matchers.match_telnet("message")
        ),
        'channel_matcher': matchers.match_channel(c.TARGETED),
        'triggers': [
            trigger.Trigger('run playbook', takes_args=True),
        ],
        'args': {
            'order': [
                'playbook',
                'inventory',
                'tags',
                'limit',
                'check',
                'remote_user',
                'forks',
                'verbosity',
            ],
            'allow_extras': True,
            'help': {
                'tags': 'feed this to ansible-playbook --tags',
                'limit': 'feed this to ansible-playbook --limit',
                'check': 'whether or not to run in --check mode',
                'remote_user': 'connect to target machines as this user',
                'forks': 'number of parallel processes to use',
                'verbosity': ('set ansible verbosity'
                              ' to this level'
                              ' (max of %s)' % ansible_utils.MAX_VERBOSE),
            },
            'converters': {
                'check': hu.strict_bool_from_string,
                'forks': utils.pos_int,
                'verbosity': int,
            },
            'defaults': {
                'tags': '',
                'limit': '',
                'check': False,
                'remote_user': 'svcact',
                'forks': 5,
                'verbosity': 0,
            },
            # NOTE: schema and help/inventories are added in at setup class
            # time and are not hardcoded in here (they involve a semi
            # dynamic finding of other environments so need to be done
            # later).
        },
        'authorizer': auth.user_in_ldap_groups('admins'),
    }
    required_clients = ('github',)

    @classmethod
    def setup_class(cls, bot):
        invs = {}
        try:
            invs.update(bot.config.ansible.inventories)
        except AttributeError:
            pass
        try:
            extra_invs_func = bot.config.ansible.extra_inventories_func
        except AttributeError:
            extra_invs_func = None
        if extra_invs_func is not None:
            extra_invs_func = utils.import_func(extra_invs_func)
            invs.update(extra_invs_func(bot.config))
        cls.handles_what['inventories'] = invs
        plays = {}
        try:
            plays.update(bot.config.ansible.playbooks)
        except AttributeError:
            pass
        try:
            extra_playbooks_func = bot.config.ansible.extra_playbooks_func
        except AttributeError:
            extra_playbooks_func = None
        if extra_playbooks_func is not None:
            extra_playbooks_func = utils.import_func(extra_playbooks_func)
            plays.update(extra_playbooks_func(bot.config))
        cls.handles_what['playbooks'] = plays
        cls.handles_what['args']['help']['inventory'] = (
            'inventory to use (one of %s)' % ", ".join(
                sorted(invs.keys())))
        cls.handles_what['args']['help']['playbook'] = (
            'playbook to run (one of %s)' % ", ".join(
                sorted(plays.keys())))
        cls.handles_what['args']['schema'] = Schema({
            Required("playbook"): All(
                scu.string_types(), Length(min=1),
                scu.one_of(sorted(plays.keys()))),
            Required("inventory"): All(
                scu.string_types(), Length(min=1),
                scu.one_of(sorted(invs.keys()))),
            Required("remote_user"): scu.string_types(),
            Required("verbosity"): All(
                int, Range(min=0, max=ansible_utils.MAX_VERBOSE)),
            Required("forks"): All(
                int, Range(min=1, max=ansible_utils.MAX_FORKS)),
            Optional("tags"): scu.string_types(),
            Optional("limit"): scu.string_types(),
            Optional("check"): bool,
        }, extra=ALLOW_EXTRA)

    @classmethod
    def insert_periodics(cls, bot, scheduler):
        try:
            plays = list(bot.config.ansible.periodics)
        except AttributeError:
            plays = []
        slack_client = bot.clients.get("slack_client")
        slack_sender = bot.slack_sender
        if slack_client is not None and slack_sender is not None:
            for play in plays:
                play = play.copy()
                play_channel = play.pop(
                    "channel", bot.config.get('periodic_channel'))
                if not play_channel:
                    play_channel = bot.config.admin_channel
                play_period = play.pop("period")
                play_trigger = cron.CronTrigger.from_crontab(
                    play_period, timezone=bot.config.tz)
                play_runner = peu.make_periodic_runner(
                    "playbook", cls, play_period, play_channel,
                    args=play, log=LOG)
                play_runner.__module__ = __name__
                play_runner.__name__ = 'run_playbook'
                play_name = reflection.get_callable_name(play_runner)
                play_description = "\n".join([
                    ("Periodic playbook running"
                     " play '%s' targeting"
                     " inventory '%s'") % (play['playbook'],
                                           play['inventory']),
                    "",
                    "With parameters:",
                    utils.prettify_yaml(play, explicit_end=False,
                                        explicit_start=False),
                    "",
                    "To channel: %s" % play_channel,
                ])
                scheduler.add_job(
                    play_runner, trigger=play_trigger,
                    jobstore='memory',
                    coalesce=True,
                    name="\n".join([play_name, play_description]),
                    id=utils.hash_pieces([play_name,
                                          play_description,
                                          play_period], max_len=8),
                    args=(bot, slack_client, slack_sender))

    @classmethod
    def is_enabled(cls, bot):
        enabled = super(PlaybookHandler, cls).is_enabled(bot)
        if not enabled:
            return False
        all_found = utils.can_find_all_executables(
            ["ansible-playbook", 'render-ansible', 'git'], logger=LOG)
        if not all_found:
            return False
        if (len(cls.handles_what['playbooks']) == 0 or
                len(cls.handles_what['inventories']) == 0):
            return False
        else:
            return True

    def _notify_admins_forced(self, playbook,
                              playbook_cmd, users_who_forced):
        who_authorized = []
        for _username, user_id in sorted(users_who_forced):
            who_authorized.append("<@" + str(user_id) + ">")
        small_playbook_cmd = playbook_cmd[0:100]
        if len(playbook_cmd) > 100:
            small_playbook_cmd += "..."
        quick_link = self.message.body.get("quick_link")
        if not quick_link:
            quick_link = "???"
        else:
            quick_link = "<%s|thread>" % quick_link
        attachment = {
            'pretext': (":warning:"
                        " An anomaly has been detected during"
                        " the missile launch"
                        " confirmation of playbook `%s`") % playbook,
            'mrkdwn_in': ['pretext', 'text'],
            'color': su.COLORS.orange,
            'text': ("Execution of `%s` has"
                     " been forced at %s by"
                     " %s.") % (small_playbook_cmd, quick_link,
                                ", ".join(who_authorized)),
        }
        self.message.reply_attachments(
            attachments=[attachment], log=LOG, link_names=True,
            as_user=True, text=' ', channel=self.config.admin_channel,
            unfurl_links=True)

    def _run(self, playbook, inventory,
             # Various ansible pass-through arguments (already converted
             # and ready to go); order defined by order in above
             # handles_what dictionary and conversions applied above.
             tags, limit, check, remote_user,
             forks, verbosity, **extra_vars):
        internally_provided = \
            self.message.headers.get(m.IS_INTERNAL_HEADER, False)

        replier = functools.partial(self.message.reply_text,
                                    threaded=True, prefixed=False)

        tmp_dir_prefix = "ansible_playbook_{}".format(playbook)

        plays = self.handles_what['playbooks']
        playbook_settings = plays[playbook]
        playbook_name = playbook
        playbook_repo = playbook_settings['repo']
        playbook_path = playbook_settings['path']
        playbook_ref = playbook_settings.get('ref')
        playbook_deps = playbook_settings.get('dependencies', [])

        invs = self.handles_what['inventories']
        inventory_settings = invs[inventory]
        run_kwargs = {}

        with utils.make_tmp_dir(dir=self.bot.config.working_dir,
                                prefix=tmp_dir_prefix) as tmp_dir:
            replier("Initiating playbook repository"
                    " clone from `%s`." % playbook_repo)
            r = pu.run(['git', 'clone', playbook_repo, 'playbook-repo'],
                       cwd=tmp_dir)
            r.raise_for_status()

            if playbook_ref:
                replier("Initiating checkout of"
                        " playbook repository"
                        " reference `%s`." % playbook_ref)
                r = pu.run(['git', 'checkout', playbook_ref],
                           cwd=os.path.join(tmp_dir, 'playbook-repo'))
                r.raise_for_status()
            playbook_path = os.path.join(
                tmp_dir, 'playbook-repo', playbook_path)

            if 'inventory_override' in playbook_settings:
                inv_arg = os.path.join(tmp_dir, 'inventory.ini')
                with open(inv_arg, 'wb') as fh:
                    fh.write(playbook_settings['inventory_override'])
                replier("Inventory `%s` has been overridden." % inventory)
            else:
                if inventory_settings['kind'] == 'git':
                    inventory_path = inventory_settings['path']
                    inventory_ref = inventory_settings.get('ref')
                    inventory_repo = inventory_settings.get(
                        'repo', playbook_repo)
                    replier("Initiating inventory repository"
                            " clone from `%s`." % inventory_repo)
                    r = pu.run(['git', 'clone', inventory_repo,
                                'inventory-repo'], cwd=tmp_dir)
                    r.raise_for_status()
                    if inventory_ref:
                        replier("Initiating checkout of"
                                " inventory repository"
                                " reference `%s`." % inventory_ref)
                        r = pu.run(['git', 'checkout', inventory_ref],
                                   cwd=os.path.join(tmp_dir, 'inventory-repo'))
                        r.raise_for_status()
                    if inventory_repo != playbook_repo:
                        inv_arg = os.path.join(
                            tmp_dir, 'inventory-repo', inventory_path)
                    else:
                        inv_arg = os.path.join(
                            tmp_dir, 'playbook-repo', inventory_path)
                elif inventory_settings['kind'] == 'static':
                    inv_arg = utils.find_executable("render-ansible")
                else:
                    raise RuntimeError(
                        "Unexpected inventory"
                        " kind '%s' matched" % inventory_settings['kind'])

            vault_path = None
            if 'vault_pass_key' in inventory_settings:
                vault_pass_path = inventory_settings['vault_pass_key']
                vault_pass = utils.dict_or_munch_extract(
                    self.bot.config, vault_pass_path)
                vault_path = _setup_vault_pass(vault_pass, tmp_dir)
            elif 'vault_pass_env' in inventory_settings:
                vault_pass_env_key = inventory_settings['vault_pass_env']
                vault_pass = os.environ[vault_pass_env_key]
                vault_path = _setup_vault_pass(vault_pass, tmp_dir)

            runner = ansible_utils.PlaybookRun(inventory=inv_arg,
                                               vault_path=vault_path,
                                               tags=tags, limit=limit,
                                               check=check,
                                               remote_user=remote_user,
                                               forks=forks,
                                               verbosity=verbosity)

            playbook_deps_locations = {}
            if playbook_deps:
                play_deps_dir = os.path.join(tmp_dir, 'dependencies')
                utils.safe_make_dirs(play_deps_dir)
                for dep in playbook_deps:
                    dep_branch = dep.get("branch")
                    clone_msg = "Cloning `%s` from `%s`" % (dep.name, dep.repo)
                    if dep_branch:
                        clone_msg += " on branch `%s`" % dep_branch
                    clone_msg += "."
                    replier(clone_msg)
                    cmd = ['git', 'clone']
                    if dep_branch:
                        cmd.extend(['--branch', dep_branch])
                    cmd.extend([dep.repo, dep.name])
                    r = pu.run(cmd, cwd=play_deps_dir)
                    r.raise_for_status()
                    playbook_deps_locations[dep.name] = os.path.join(
                        play_deps_dir, dep.name)

            if 'extra_vars' in playbook_settings:
                ev = playbook_settings['extra_vars']
                for k, v in ev.items():
                    runner.set_extra_var(k, v)
            if 'extra_vars_func' in playbook_settings:
                extra_vars_func = playbook_settings['extra_vars_func']
                extra_vars_func = utils.import_func(extra_vars_func)
                ev = extra_vars_func(tmp_dir, playbook_deps_locations,
                                     vault_path=vault_path)
                for k, v in ev.items():
                    runner.set_extra_var(k, v)
            for k, v in extra_vars.items():
                runner.set_extra_var(k, v)

            retry = playbook_settings.get("retry")
            if not retry:
                retry = munch.Munch({
                    'count': 0,
                })
            playbook_short_name = os.path.basename(playbook_path)
            start_msg = "Starting run of playbook: `%s`" % playbook_short_name
            if retry.count > 0:
                start_msg += " (retries=%s)" % (retry.count)
            replier(start_msg)
            playbook_cmd = runner.form_command(
                playbook_short_name, printable=True)
            playbook_cmd = " ".join(playbook_cmd)

            needs_signoff = playbook_settings.get("needs_signoff", True)
            allow_selfsign = playbook_settings.get("allow_self_signoff", False)
            if check or internally_provided:
                needs_signoff = False
            if 'skip_confirm_extra_var' in playbook_settings:
                skip_confirm_ev = runner.get_extra_var(
                    playbook_settings['skip_confirm_extra_var'],
                    default=False)
                if strutils.bool_from_string(skip_confirm_ev):
                    needs_signoff = False
            if needs_signoff:
                replier("Please confirm the execution"
                        " of `%s`." % playbook_cmd)
                f = followers.ConfirmMe(confirms_what='playbook execution',
                                        confirm_self_ok=allow_selfsign)
                replier(f.generate_who_satisifies_message(self))
                self.wait_for_transition(wait_timeout=300,
                                         wait_start_state='CONFIRMING',
                                         follower=f)
                if self.state == 'CONFIRMED_CANCELLED':
                    replier("Execution cancelled.")
                    return
                else:
                    if f.confirms_forced:
                        self._notify_admins_forced(
                            playbook_short_name, playbook_cmd,
                            f.confirms_forced)

            run_env = utils.get_environ()
            for s in (inventory_settings, playbook_settings):
                if 'env' in s:
                    run_env.update(s['env'])
            if vault_path:
                run_env['VAULT_PASSWORD_FILE'] = vault_path
            run_kwargs['env'] = run_env

            try:
                max_gist_mb = self.config.ansible.max_gist_mb
            except AttributeError:
                max_gist_mb = None

            replier("Running `%s`" % playbook_cmd)
            replier(random.choice(LAUNCH_LINES))

            self.change_state("EXECUTING")
            f = followers.StopExecution()
            self.followers.append(f)
            try:
                res = self._run_runner_run(
                    tmp_dir, replier, runner, playbook_path,
                    "Happily ran `%s` playbook." % playbook_name,
                    "Failed running `%s` playbook." % playbook_name,
                    run_kwargs=run_kwargs,
                    pbar=self.message.make_manual_progress_bar(),
                    max_gist_mb=max_gist_mb)
            finally:
                self.followers.remove(f)

            retry_hosts = None
            retry_path = None
            for i in compat_range(0, retry.count):
                if retry_hosts is None or retry_path is None:
                    retry_hosts, retry_path = _extract_retry_hosts(
                        tmp_dir, playbook_path)
                if not retry_hosts or res.was_ok() or self.dead.is_set():
                    break
                runner.limit = ",".join(sorted(retry_hosts))
                os.rename(retry_path, "%s.%s" % (retry_path, i))
                playbook_cmd = runner.form_command(
                    playbook_short_name, printable=True)
                replier("Auto retrying `%s` for the %s"
                        " time (against %s"
                        " hosts)." % (" ".join(playbook_cmd),
                                      utils.to_ordinal(i + 1),
                                      len(retry_hosts)))
                replier(random.choice(LAUNCH_LINES))
                retry_hosts = None
                retry_path = None
                self.change_state("EXECUTING")
                f = followers.StopExecution()
                self.followers.append(f)
                try:
                    res = self._run_runner_run(
                        tmp_dir, replier, runner, playbook_path,
                        "Happily re-ran `%s` playbook." % playbook_name,
                        "Failed re-running `%s` playbook." % playbook_name,
                        run_kwargs=run_kwargs,
                        pbar=self.message.make_manual_progress_bar(),
                        max_gist_mb=max_gist_mb)
                finally:
                    self.followers.remove(f)
                retry_hosts, retry_path = _extract_retry_hosts(
                    tmp_dir, playbook_path)
                if not res.was_ok() and (i + 1 < retry.count) and retry_hosts:
                    try:
                        wait_between = retry.wait_between
                    except AttributeError:
                        pass
                    else:
                        replier("Idling %0.2f seconds before"
                                " trying again." % wait_between)
                        try:
                            self.wait_for_transition(
                                follower=followers.CancelMe(),
                                wait_timeout=wait_between,
                                wait_start_state='IDLING')
                        except (excp.WaitTimeout, excp.Dying):
                            pass
                        if self.state == 'CANCELLED':
                            break

            # NOTE: this will do nothing if the result was good.
            res.raise_for_status()
