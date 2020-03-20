import json
import logging
from urllib.parse import parse_qs
from urllib.parse import urlparse

import oidcrp
import werkzeug
from flask import Blueprint
from flask import Response
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask.helpers import make_response
from flask.helpers import send_from_directory

logger = logging.getLogger(__name__)

oidc_rp_views = Blueprint('oidc_rp', __name__, url_prefix='')


def compact(qsdict):
    res = {}
    for key, val in qsdict.items():
        if len(val) == 1:
            res[key] = val[0]
        else:
            res[key] = val
    return res


@oidc_rp_views.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)


@oidc_rp_views.route('/rp/<test_id>')
def rp(test_id):
    _info = current_app.rph.phase0(test_id)
    try:
        return redirect(_info['url'], 303)
    except:
        if isinstance(_info, dict):
            return make_response(json.dumps(_info), 400)
        else:
            return make_response(_info, 200)


def get_rp(op_hash):
    try:
        _rp = current_app.rph.test_id2rp[op_hash]
    except KeyError:
        return make_response("Unknown hash: {}".format(op_hash), 400)

    return _rp


def finalize(op_hash, request_args):
    rp = get_rp(op_hash)
    if isinstance(rp, Response):
        return rp

    try:
        session['client_id'] = rp.service_context.registration_response['client_id']
    except KeyError:
        session['client_id'] = rp.service_context.client_id

    session['state'] = request_args['state']
    try:
        iss = rp.session_interface.get_iss(request_args['state'])
    except KeyError:
        return make_response('Unknown state', 400)

    try:
        session['session_state'] = request_args['session_state']
    except KeyError:
        session['session_state'] = ''

    logger.debug('Issuer: {}'.format(iss))
    res = current_app.rph.phaseN(rp, request_args)

    if isinstance(res, dict):
        if 'http_response' in res:
            _http_response = res["http_response"]
            loc = _http_response.headers['location']
            return redirect(loc, _http_response.status_code)
        else:
            return make_response(res['error'], 400)
    elif res == "OK":
        return make_response('OK', 200)
    else:
        return make_response(res, 400)


@oidc_rp_views.route('/authz_cb/<op_hash>')
def authz_cb(op_hash):
    return finalize(op_hash, request.args)


@oidc_rp_views.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400


@oidc_rp_views.route('/repost_fragment')
def repost_fragment():
    args = compact(parse_qs(request.args['url_fragment']))
    op_hash = request.args['op_hash']
    return finalize(op_hash, args)


@oidc_rp_views.route('/ihf_cb')
def ihf_cb(self, op_hash='', **kwargs):
    logger.debug('implicit_hybrid_flow kwargs: {}'.format(kwargs))
    return render_template('repost_fragment.html')


def _session_iframe(looked_for_state, op_hash):  # session management
    logger.debug("Render session iframe")
    _rp = get_rp(op_hash)

    session_change_url = "{}/session_change/{}".format(
        _rp.service_context.base_url, op_hash)

    _part = urlparse(_rp.service_context.issuer)
    _issuer = "{}://{}".format(_part.scheme, _part.netloc)

    args = {
        'client_id': session['client_id'],
        'session_state': session['session_state'],
        'issuer': _issuer,
        'session_change_url': session_change_url,
        'looked_for_state': looked_for_state
    }
    logger.debug('rp_iframe args: {}'.format(args))
    _rp_iframe_path = _rp.service_context.add_on['status_check']['rp_iframe_path']
    _page = render_template(_rp_iframe_path, **args)
    return _page


@oidc_rp_views.route('/session_verify_changed/<op_hash>')
def session_verify_changed(op_hash):  # session management
    logger.debug('session_verify_changed request_args: {}'.format(request.args))
    return _session_iframe("changed", op_hash)


@oidc_rp_views.route('/session_verify_unchanged/<op_hash>')
def session_verify_unchanged(op_hash):  # session management
    logger.debug('session_verify_unchanged request_args: {}'.format(request.args))
    return _session_iframe("unchanged", op_hash)


@oidc_rp_views.route('/session_change/<op_hash>')
def session_change(op_hash):
    logger.debug('session_change: {}'.format(op_hash))
    _rp = get_rp(op_hash)
    res = current_app.rph.run(_rp, session["state"])
    logger.debug("res: %s", res)
    if isinstance(res, dict):
        if 'http_response' in res:
            _http_response = res["http_response"]
            loc = _http_response.headers['location']
            return redirect(loc, _http_response.status_code)
        else:
            return make_response(res['error'], 400)
    else:
        return make_response(res, 200)


# post_logout_redirect_uri
@oidc_rp_views.route('/post_logout/<op_hash>')
def session_logout(op_hash):
    logger.debug('post_logout')
    _rp = get_rp(op_hash)
    _rp.service_context.service_index += 1
    _logout_state = request.args.get("state")
    if _logout_state:
        # verify that it's a correct state value
        try:
            _state = _rp.session_interface.get_state_by_x(_logout_state, 'logout state')
        except KeyError:
            logger.debug("Incorrect state value returned")
            return make_response("Incorrect state value returned", 400)
        res = current_app.rph.run(_rp, _state)
    else:
        if "state" in session:
            logger.debug("Provided state value was not returned")
            return make_response("Provided state value was not returned")
        res = current_app.rph.run(_rp)

    if isinstance(res, dict):
        if 'http_response' in res:
            _http_response = res["http_response"]
            loc = _http_response.headers['location']
            return redirect(loc, _http_response.status_code)
        else:
            return make_response(res['error'], 400)
    else:
        logger.debug(res)
        return make_response(res, 200)


# RP initiated logout
@oidc_rp_views.route('/logout/<op_hash>')
def logout(op_hash):
    logger.debug('logout')
    _rp = get_rp(op_hash)
    _info = current_app.rph.logout(state=session['state'])
    logger.debug('logout redirect to "{}"'.format(_info['url']))
    return redirect(_info['url'], 303)


@oidc_rp_views.route('/bc_logout/<op_hash>', methods=['POST'])
def backchannel_logout(op_hash):
    logger.debug("Backchannel logout")
    _rp = get_rp(op_hash)

    logout_token = request.form['logout_token']
    try:
        _state = oidcrp.backchannel_logout(_rp, request_args={'logout_token': logout_token})
    except Exception as err:
        logger.error('Exception: {}'.format(err))
        return '{}'.format(err), 400
    else:
        _rp.session_interface.remove_state(_state)
        session['logout'] = op_hash
        logger.debug("OK")
        return "OK"


@oidc_rp_views.route('/fc_logout/<op_hash>', methods=['GET', 'POST'])
def frontchannel_logout(op_hash):
    logger.debug("Frontchannel logout")
    _rp = get_rp(op_hash)
    sid = request.args['sid']
    _iss = request.args['iss']
    if _iss != _rp.service_context.issuer:
        return 'Bad request', 400
    session['logout'] = op_hash
    _state = _rp.session_interface.get_state_by_sid(sid)
    _rp.session_interface.remove_state(_state)
    logger.debug("OK")
    return "OK"
