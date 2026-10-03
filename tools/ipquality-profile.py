"""Bind the exact offline IPQuality selection to every factory phase.

Public proof contains only fixed material inventories and reproducible code or
selection digests. Host identities and replay evidence stay in private factory
directories. Neither evidence format approves a builder or a license.
"""
import importlib.util
from contextlib import contextmanager
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROFILE = 'ipquality-node-v1'
KIND = 'sinan-ipquality-minimal-profile'
PUBLIC_NAME = 'ipquality-profile.json'
PRIVATE_NAME = 'ipquality-profile-private.json'
CODE_FILES = ('tools/ipquality-profile.py', 'tools/ipquality-rootfs.py',
              'tools/ipquality-inputs.py', 'tools/ipquality-inputs-capacity.py',
              'tools/nodequality-rootfs-build.py', 'tools/nodequality-rootfs-collect.py',
              'plugins/nodequality/rootfs.py')
FALSE_FLAGS = ('builder_approved', 'runtime_image_identity_verified',
               'reproducibility_verified', 'full_ready')


def inputs():
    specification = importlib.util.spec_from_file_location('sinan_ipquality_profile_inputs',
                                                         ROOT / 'tools/ipquality-inputs.py')
    result = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(result)
    return result


class Profile:
    def __init__(self, build, commands):
        self.build, self.commands = build, dict(commands)
        self.prepare_context = None
        self.scratch_ownership = {}

    def ensure_cleanup_safe(self, output):
        """A parent cleanup must not erase a replaced nested replay directory."""
        requested = Path(output).absolute()
        for scratch, identity in self.scratch_ownership.items():
            if scratch == requested or scratch.is_relative_to(requested):
                self.build.require(identity is not None
                                   and self.build.FactoryCapacity.identity(scratch) == identity[0]
                                   and self.build.FactoryCapacity.identity(scratch.parent) == identity[1],
                                   'cleanup blocked by replaced minimal profile scratch')
                self.build.ensure_no_mounts(scratch)

    @contextmanager
    def owned_scratch(self, parent, prefix):
        build = self.build
        scratch, identity = None, None
        try:
            with build.deferred_signals():
                scratch = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
                self.scratch_ownership[scratch] = None
                identity = build.FactoryCapacity.identity(scratch), build.FactoryCapacity.identity(scratch.parent)
                self.scratch_ownership[scratch] = identity
            yield scratch
        except BaseException as error:
            if scratch is not None:
                error.factory_profile_scratch = str(scratch)
            raise
        finally:
            if scratch is not None:
                if identity is None:
                    # A newly created directory whose identity could not be
                    # recorded cannot safely be claimed or deleted.
                    if sys.exc_info()[1] is not None and hasattr(sys.exc_info()[1], 'add_note'):
                        sys.exc_info()[1].add_note('Minimal profile scratch ownership is unknown; directory retained')
                else:
                    removed = build.cleanup_output(scratch, guard_mounts=True, expected_identity=identity)
                    if removed:
                        del self.scratch_ownership[scratch]
                    elif sys.exc_info()[1] is None:
                        raise ValueError('minimal profile scratch cleanup failed; directory retained')

    @contextmanager
    def admission(self, parent, deadline, operation):
        """Standalone verification owns separate evidence, never its input tree."""
        if deadline.capacity is not None:
            yield
            return
        build, derive = self.build, inputs()
        helper = derive.modules()['capacity']
        plan = derive.output_plan(build, parent, build.DEFAULT_MAX_OUTPUT, build.DEFAULT_RESERVE_FREE)
        build.require(plan['admitted'], 'minimal profile verification capacity rejected')
        previous, evidence, failure, output = deadline.capacity, None, None, None
        try:
            with self.owned_scratch(parent, 'ipquality-profile-verification-') as output:
                guard = self.guard(build.FactoryCapacity(output, plan, deadline), helper, derive)
                deadline.capacity = guard
                guard.check(force=True)
                yield
                guard.finish()
        except BaseException as error:
            failure = error
            if output is None and getattr(error, 'factory_profile_scratch', None) is not None:
                output = Path(error.factory_profile_scratch)
            if output is not None:
                evidence = build.preserve_factory_failure(output, operation, error, deadline.capacity)
            raise
        finally:
            deadline.capacity = previous
            if output is not None:
                build.record_factory_cleanup(evidence, output not in self.scratch_ownership, failure)

    def guard(self, capacity, helper, derive):
        if getattr(capacity, '_ipquality_profile_guard', False):
            return capacity
        result = derive.Guard(capacity, helper)
        result._ipquality_profile_guard = True
        return result

    def require_prepare_context(self, output=None, deadline=None):
        self.build.require(isinstance(self.prepare_context, dict)
                           and set(self.prepare_context) == {'derived_inputs', 'derived_binding'}
                           and all(isinstance(path, (str, Path)) and bool(str(path))
                                   for path in self.prepare_context.values()),
                           'IPQuality prepare requires explicit derived inputs and binding')
        if output is not None:
            self.deny_input_overlap(self.prepare_context, output, deadline)

    def deny_input_overlap(self, context, output, deadline=None):
        build = self.build
        build.require(isinstance(context, dict) and set(context) == {'derived_inputs', 'derived_binding'}
                      and all(isinstance(path, (str, Path)) and bool(str(path)) for path in context.values()),
                      'private minimal profile context is incomplete')
        paths = [Path(path).absolute() for path in context.values()]
        requested = Path(output).absolute()
        build.require('..' not in requested.parts
                      and all('..' not in path.parts for path in paths)
                      and all(not requested.is_relative_to(path) and not path.is_relative_to(requested)
                              for path in paths),
                      'minimal preparation output overlaps original inputs')
        derive = inputs()
        deadline = deadline or build.Deadline(build.PREPARE_SECONDS)
        derived, _ = derive.directory(context['derived_inputs'])
        raw, _ = derive.read_snapshot(build, derived / 'derivation.json', build.MAX_METADATA, deadline)
        receipt = build.decode(raw)
        # This untrusted receipt is used only to deny an unsafe location.
        # No positive admission or authentication relies on it here.
        parent = receipt.get('parent') if isinstance(receipt, dict) else None
        build.require(isinstance(parent, dict) and isinstance(parent.get('directory'), str),
                      'derived input parent location is absent')
        parent_path, _ = derive.directory(parent['directory'])
        output_parent, _ = derive.directory(requested.parent)
        requested = output_parent / requested.name
        build.require(not requested.is_relative_to(parent_path)
                      and not parent_path.is_relative_to(requested),
                      'minimal preparation output overlaps original inputs (parent)')

    def code(self, deadline):
        return {name: self.build.file_identity(ROOT / name, self.build.MAX_LOCK, deadline)['sha256']
                for name in CODE_FILES}

    def selection(self, solver, materials):
        build = self.build
        keys = ('schema', 'seeds', 'main_essential_names', 'package_selection',
                'installation', 'binary_downloads_by_solver')
        build.require(isinstance(solver, dict) and all(key in solver for key in keys),
                      'minimal profile solver evidence is incomplete')
        build.require(type(solver['schema']) is int and solver['schema'] == 1
                      and solver['installation'] is False and solver['binary_downloads_by_solver'] is False,
                      'minimal profile solver cannot install or download')
        for name in ('seeds', 'main_essential_names'):
            rows = solver[name]
            build.require(isinstance(rows, list) and 0 < len(rows) <= 2048
                          and all(isinstance(value, str) and build.NAME.fullmatch(value) for value in rows)
                          and rows == sorted(set(rows)), 'invalid minimal profile solver seeds')
        build.require(solver['seeds'] == sorted(set(solver['main_essential_names'])
                      | {'apt'} | set(self.commands.values())), 'minimal profile seed set differs')
        expected = [{key: value for key, value in row.items() if key != 'blob'}
                    for row in materials['packages']]
        build.require(solver['package_selection'] == expected,
                      'minimal profile package inventory differs from solver')
        namespaces = solver.get('network_namespaces')
        build.require(isinstance(namespaces, list) and len(namespaces) == 2,
                      'minimal profile namespace evidence is incomplete')
        selected = []
        for operation, row in zip(('update', 'plan'), namespaces):
            build.require(isinstance(row, dict) and type(row.get('schema')) is int and row['schema'] == 1
                          and row.get('operation') == operation and row.get('different_namespace') is True
                          and row.get('interfaces') == ['lo'] and row.get('installation') is False,
                          'minimal profile solver isolation differs')
            selected.append({key: row[key] for key in ('schema', 'operation', 'different_namespace',
                                                      'interfaces', 'installation')})
        return {**{key: solver[key] for key in keys}, 'network_namespaces': selected}

    def validate_public(self, proof, lock, deadline=None, implementation=None):
        """Validate signed selection shape, not substitute it for fresh admission."""
        build = self.build
        build.validate_lock(lock)
        fields = {'schema', 'kind', 'profile', 'arch', 'source_epoch', 'commands', 'materials',
                  'materials_sha256', 'selection', 'selection_sha256', 'parent_materials_sha256',
                  'parent_collection_sha256', 'derived_selection_sha256', 'binding_inputs_lock_sha256',
                  'implementations', *FALSE_FLAGS}
        build.require(isinstance(proof, dict) and set(proof) == fields
                      and type(proof['schema']) is int and proof['schema'] == 1
                      and proof['kind'] == KIND and proof['profile'] == PROFILE
                      and proof['arch'] == lock['arch'] and type(proof['source_epoch']) is int
                      and proof['source_epoch'] == lock['source_epoch'] and proof['commands'] == self.commands,
                      'invalid minimal IPQuality profile proof')
        build.require(all(proof[name] is False for name in FALSE_FLAGS),
                      'minimal profile proof cannot approve execution')
        materials = {key: value for key, value in lock.items() if key != 'builder'}
        build.require(proof['materials'] == materials
                      and proof['materials_sha256'] == build.digest(build.canonical(materials) + b'\n')
                      and proof['binding_inputs_lock_sha256'] == build.digest(build.canonical(lock) + b'\n'),
                      'minimal profile exact package/source binding differs')
        selection = self.selection(proof['selection'], materials)
        build.require(proof['selection'] == selection
                      and proof['selection_sha256'] == build.digest(build.canonical(selection) + b'\n'),
                      'minimal profile public selection identity differs')
        for name in ('materials_sha256', 'selection_sha256', 'parent_materials_sha256',
                     'parent_collection_sha256', 'derived_selection_sha256', 'binding_inputs_lock_sha256'):
            build.require(isinstance(proof[name], str) and build.SHA256.fullmatch(proof[name]),
                          'invalid minimal profile digest')
        expected = implementation if implementation is not None else self.code(deadline)
        build.require(isinstance(proof['implementations'], dict) and set(proof['implementations']) == set(CODE_FILES)
                      and proof['implementations'] == expected
                      and all(isinstance(value, str) and build.SHA256.fullmatch(value)
                              for value in proof['implementations'].values()),
                      'minimal profile implementation identity differs')
        build.require(len(build.canonical(proof) + b'\n') <= build.MAX_METADATA,
                      'minimal profile proof exceeds runtime metadata bound')
        return proof

    def authenticate_binding(self, context, lock, cache, deadline, loaded):
        """Reauthenticate all parent bodies and binding evidence before replay."""
        derive, build = loaded['inputs'], self.build
        build.require(isinstance(context, dict) and set(context) == {'derived_inputs', 'derived_binding'},
                      'private minimal profile context is incomplete')
        derived, _ = derive.directory(context['derived_inputs'])
        binding, binding_identity = derive.directory(context['derived_binding'])
        build.require(not binding.is_relative_to(derived) and not derived.is_relative_to(binding),
                      'minimal profile binding overlaps derived input')
        verified = derive.verify_derivation(derived, deadline, loaded['modules'])
        build.require(derive.directory(cache)[0] == verified['parent']['cache'],
                      'minimal profile cache differs from authenticated parent')
        names = ('binding.json', 'inputs-lock.json', 'candidate-builder.json',
                 'expanded-indices.json', 'tool-evidence.json', 'solver/selection.json')
        values, snapshots = {}, {}
        for name in names:
            content, identity = derive.read_snapshot(build, binding / name, build.MAX_LOCK, deadline)
            values[name], snapshots[name] = build.decode(content), identity
        receipt = values['binding.json']
        fields = {'schema', 'kind', 'profile', 'arch', 'derivation_directory', 'derivation_sha256',
                  'materials_sha256', 'inputs_lock_sha256', 'cache_directory', 'parent_collection_sha256',
                  'lock_ready', *FALSE_FLAGS, 'installation', 'network_requests', 'payload_downloads'}
        build.require(isinstance(receipt, dict) and set(receipt) == fields
                      and type(receipt['schema']) is int and receipt['schema'] == 1
                      and receipt['kind'] == derive.KIND + '-binding' and receipt['profile'] == PROFILE
                      and receipt['arch'] == lock['arch'] and receipt['derivation_directory'] == str(derived)
                      and receipt['derivation_sha256'] == verified['derivation_sha256']
                      and receipt['materials_sha256'] == verified['receipt']['files_sha256']['materials.json']
                      and receipt['inputs_lock_sha256'] == snapshots['inputs-lock.json']['sha256']
                      and receipt['cache_directory'] == str(verified['parent']['cache'])
                      and receipt['parent_collection_sha256'] == verified['parent']['receipt_sha256']
                      and receipt['lock_ready'] is True
                      and all(receipt[name] is False for name in (*FALSE_FLAGS, 'installation',
                                                                 'network_requests', 'payload_downloads')),
                      'derived binding receipt differs from authenticated inputs')
        build.require(values['inputs-lock.json'] == lock
                      and receipt['inputs_lock_sha256'] == build.digest(build.canonical(lock) + b'\n')
                      and {key: value for key, value in lock.items() if key != 'builder'} == verified['child'],
                      'derived binding changed the exact minimal package/source inventory')
        candidate = loaded['modules']['collect'].verify_candidate(values['candidate-builder.json'], lock['arch'], deadline)
        build.require(candidate == lock['builder'], 'derived binding candidate differs from input lock')
        derive.verify_tools(values['tool-evidence.json'], build, deadline)
        derived_bounds = loaded['modules']['capacity'].authenticated_expansion(
            verified['parent']['materials'], verified['parent']['cache'], deadline)
        build.require(values['expanded-indices.json'] == derived_bounds,
                      'derived binding signed expansion differs')
        original_solver = build.decode(build.read_regular(derived / 'solver/selection.json', build.MAX_LOCK, deadline))
        build.require(self.selection(values['solver/selection.json'], verified['child'])
                      == self.selection(original_solver, verified['child']),
                      'derived binding solver changed the minimal profile')
        return verified, binding, binding_identity, snapshots

    def replay(self, context, lock, cache, deadline):
        build, derive = self.build, inputs()
        loaded = {'inputs': derive, 'modules': derive.modules()}
        guard = deadline.capacity
        build.require(guard is not None and hasattr(guard, 'output'),
                      'minimal profile admission requires an owned output guard')
        self.deny_input_overlap(context, guard.output, deadline)
        # Extend the existing filesystem/deadline guard with the same native
        # memory/OOM policy as derivation. All child deadlines inherit it.
        guarded = self.guard(guard, loaded['modules']['capacity'], derive)
        deadline.capacity = guarded
        guarded.check(force=True)
        verified, binding, binding_identity, snapshots = self.authenticate_binding(
            context, lock, cache, deadline, loaded)
        output = Path(guard.output).absolute()
        for directory in (verified['directory'], binding, verified['parent']['directory']):
            build.require(not output.is_relative_to(directory) and not directory.is_relative_to(output),
                          'minimal profile replay output overlaps original inputs')
        with self.owned_scratch(output, 'ipquality-profile-replay-') as temporary:
            selected, solver, _ = derive.select(verified['parent'], temporary, deadline, guarded, loaded['modules'])
            build.require(selected == verified['child'], 'fresh minimal profile replay changed package/source selection')
            selection = self.selection(solver, selected)
            code = self.code(deadline)
            proof = {'schema': 1, 'kind': KIND, 'profile': PROFILE, 'arch': selected['arch'],
                     'source_epoch': selected['source_epoch'], 'commands': self.commands, 'materials': selected,
                     'materials_sha256': build.digest(build.canonical(selected) + b'\n'),
                     'selection': selection, 'selection_sha256': build.digest(build.canonical(selection) + b'\n'),
                     'parent_materials_sha256': verified['parent']['materials_sha256'],
                     'parent_collection_sha256': verified['parent']['receipt_sha256'],
                     'derived_selection_sha256': verified['receipt']['solver_selection_sha256'],
                     'binding_inputs_lock_sha256': build.digest(build.canonical(lock) + b'\n'),
                     'implementations': code, **{name: False for name in FALSE_FLAGS}}
            derive.verify_ledger(verified['ledger'], deadline, build)
            derive.verify_code(verified['code'], build, deadline)
            derive.verify_tools(verified['tools'], build, deadline)
            build.require(derive.directory(binding)[1] == binding_identity,
                          'minimal binding directory changed during admission')
            for name, previous in snapshots.items():
                build.require(derive.snapshot_file(binding / name, build.MAX_LOCK, deadline) == previous,
                              'minimal binding evidence changed during admission')
            for name, previous in verified['sidecars'].items():
                build.require(derive.snapshot_file(verified['directory'] / name, build.MAX_LOCK, deadline) == previous,
                              'minimal derived evidence changed during admission')
            build.require(derive.directory(verified['directory'])[1] == verified['directory_identity'],
                          'minimal derived directory changed during admission')
            self.ensure_cleanup_safe(temporary)
            self.validate_public(proof, lock, deadline, code)
            guarded.write(output / ('ipquality-profile-replay-' + Path(temporary).name + '.json'),
                          build.canonical({'schema': 1, 'selection': solver, 'binding_files': snapshots,
                                           'derived_files': verified['sidecars'],
                                           'memory_observation': guarded.last_memory}) + b'\n', 0o600)
        guarded.check(force=True)
        return proof

    def prepare(self, lock, cache, output, deadline):
        self.require_prepare_context()
        build = self.build
        context = {name: str(inputs().directory(path)[0]) for name, path in self.prepare_context.items()}
        proof = self.replay(context, lock, cache, deadline)
        content = build.canonical(proof) + b'\n'
        deadline.capacity.write(Path(output) / PUBLIC_NAME, content)
        deadline.capacity.write(Path(output) / PRIVATE_NAME,
            build.canonical({'schema': 1, 'kind': KIND + '-private', 'context': context,
                             'cache_directory': str(inputs().directory(cache)[0]),
                             'profile_proof_sha256': build.digest(content)}) + b'\n', 0o600)
        return {'proof': proof, 'bytes': content, 'sha256': build.digest(content)}

    def verify(self, directory, lock, deadline):
        build, derive = self.build, inputs()
        public, public_identity = derive.read_snapshot(build, Path(directory) / PUBLIC_NAME, build.MAX_METADATA, deadline)
        private, private_identity = derive.read_snapshot(build, Path(directory) / PRIVATE_NAME, build.MAX_LOCK, deadline)
        proof, raw_context = build.decode(public), build.decode(private)
        self.validate_public(proof, lock, deadline)
        build.require(public == build.canonical(proof) + b'\n'
                      and isinstance(raw_context, dict) and set(raw_context) == {'schema', 'kind', 'context',
                                                                                'cache_directory', 'profile_proof_sha256'}
                      and type(raw_context['schema']) is int and raw_context['schema'] == 1
                      and raw_context['kind'] == KIND + '-private'
                      and isinstance(raw_context['cache_directory'], str)
                      and raw_context['profile_proof_sha256'] == build.digest(public),
                      'private minimal profile context binding differs')
        build.require(self.replay(raw_context['context'], lock, raw_context['cache_directory'], deadline) == proof,
                      'prepared minimal profile changed on fresh admission')
        build.require(derive.snapshot_file(Path(directory) / PUBLIC_NAME, build.MAX_METADATA, deadline) == public_identity
                      and derive.snapshot_file(Path(directory) / PRIVATE_NAME, build.MAX_LOCK, deadline) == private_identity,
                      'prepared minimal profile evidence changed during admission')
        return {'proof': proof, 'bytes': public, 'sha256': build.digest(public)}

    def verify_export(self, directory, manifest, prepared, deadline):
        """Read actual archived status and metadata after fresh prepared admission."""
        build = self.build
        specification = importlib.util.spec_from_file_location('sinan_ipquality_export_runtime',
                                                               ROOT / 'plugins/nodequality/rootfs.py')
        helper = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(helper)
        original_deadline = helper._deadline
        def checked_deadline(end):
            deadline.check()
            original_deadline(end)
        helper._deadline = checked_deadline
        names = [build.META_DIR + '/' + name for name in
                 ('provenance.json', 'inputs-lock.json', 'source-inventory.json',
                  'license-inventory.json', PUBLIC_NAME)]
        metadata = helper.read_metadata(Path(directory) / 'rootfs.tar.gz', manifest,
                                        names + ['var/lib/dpkg/status'])
        for name in names:
            build.require(metadata[name] == build.read_regular(Path(directory) / Path(name).name,
                                                               build.MAX_METADATA, deadline),
                          'minimal export archive differs from its inventory sidecar')
        installed = build.verify_installed_packages(metadata['var/lib/dpkg/status'],
                                                     prepared['lock']['packages'], exact_sources=True)
        licenses = build.decode(metadata[build.META_DIR + '/license-inventory.json'])
        build.require(licenses.get('packages') == installed,
                      'minimal export actual package status differs from license inventory')
        permitted = set(names)
        build.require(all(row['path'] in permitted for row in manifest['entries']
                          if row['path'].startswith(build.META_DIR + '/')),
                      'minimal export contains private or unreviewed factory evidence')
        return installed
