import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { runInNewContext } from 'node:vm'
import * as vue from 'vue'
import { compileScript, compileTemplate, parse } from 'vue/compiler-sfc'
import ts from 'typescript'

const flush = () => new Promise(setImmediate)

function mountProfile(authConfig) {
  const source = readFileSync(new URL('./UserProfile.vue', import.meta.url), 'utf8')
  const { descriptor } = parse(source)
  const script = compileScript(descriptor, { id: 'user-profile-test' })
  const template = compileTemplate({
    source: descriptor.template.content,
    filename: 'UserProfile.vue',
    id: 'user-profile-test',
    compilerOptions: { bindingMetadata: script.bindings },
  })
  assert.deepEqual(template.errors, [])
  const passwordRequests = []
  const imports = {
    'vue-router': { useRouter: () => ({ push() {} }) },
    'tdesign-vue-next': { MessagePlugin: { success() {}, error() {} } },
    'vue-i18n': { useI18n: () => ({ t: (key) => key, locale: vue.ref('en-US') }) },
    '@/stores/auth': { useAuthStore: () => ({ logout() {} }) },
    '@/utils/passwordPolicy': { newPasswordRules: () => [] },
    '@/api/auth': {
      getCurrentUser: async () => ({ success: true, data: { user: { id: 'user', email: 'user@example.com' } } }),
      getAuthConfig: async () => authConfig,
      changePassword: async (body) => { passwordRequests.push(body); return { success: true } },
      logout: async () => {},
    },
  }
  function evaluate(code) {
    const exports = {}
    const { outputText } = ts.transpileModule(code, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    })
    runInNewContext(outputText, {
      exports,
      require(name) {
        if (name === 'vue') return vue
        assert.ok(name in imports, `Unexpected import: ${name}`)
        return imports[name]
      },
    })
    return exports
  }
  const component = Object.assign(evaluate(script.content).default, { render: evaluate(template.code).render })
  const renderer = vue.createRenderer({
    createElement: (tag) => ({ tag, children: [], style: {} }),
    createText: (text) => ({ text }),
    createComment: (text) => ({ text }),
    insert(child, parent, anchor) {
      if (child.parent) child.parent.children = child.parent.children.filter((item) => item !== child)
      const index = anchor ? parent.children.indexOf(anchor) : -1
      parent.children.splice(index < 0 ? parent.children.length : index, 0, child)
      child.parent = parent
    },
    remove(child) {
      if (child.parent) child.parent.children = child.parent.children.filter((item) => item !== child)
      child.parent = null
    },
    parentNode: (node) => node?.parent,
    nextSibling: (node) => node.parent?.children[node.parent.children.indexOf(node) + 1] ?? null,
    setText(node, text) { node.text = text },
    setElementText(node, text) { node.children = []; node.text = text },
    patchProp(node, key, _, value) { if (key !== 'style') node[key] = value },
  })
  const passthrough = { setup: (_, { slots }) => () => vue.h('div', slots.default?.()) }
  const app = renderer.createApp(component)
  app.config.globalProperties.$t = (key) => key
  for (const name of ['t-button', 't-icon', 't-input', 't-form', 't-form-item', 't-popup', 't-loading', 't-alert']) {
    app.component(name, passthrough)
  }
  const root = { children: [] }
  app.mount(root)
  return { app, root, state: app._instance.setupState, passwordRequests }
}

function hasPasswordRow(node) {
  return node.text === 'userProfile.changePassword.label' || (node.children || []).some(hasPasswordRow)
}

for (const [name, config, allowed] of [
  ['LDAP enabled', { success: true, ldap_enabled: true }, false],
  ['LDAP disabled', { success: true, ldap_enabled: false }, true],
  ['unavailable config', { success: false }, false],
  ['unknown LDAP state', { success: true }, false],
]) {
  test(`password setting follows authentication mode: ${name}`, async (t) => {
    const { app, root, state, passwordRequests } = mountProfile(config)
    t.after(() => app.unmount())
    await flush()
    await flush()
    assert.equal(state.passwordChangeAllowed, allowed)
    assert.equal(hasPasswordRow(root), allowed)
    if (!allowed) {
      await state.submitPasswordChange()
      assert.equal(passwordRequests.length, 0)
    }
  })
}

test('refreshing authentication mode hides the password setting when LDAP becomes enabled', async (t) => {
  const config = { success: true, ldap_enabled: false }
  const { app, root, state } = mountProfile(config)
  t.after(() => app.unmount())
  await flush()
  assert.equal(hasPasswordRow(root), true)
  state.passwordPopupVisible = true
  await flush()
  state.passwordForm.oldPassword = 'example-password'
  config.ldap_enabled = true
  await state.loadPasswordPolicy()
  await flush()
  assert.equal(hasPasswordRow(root), false)
  assert.equal(state.passwordPopupVisible, false)
  assert.equal(state.passwordForm.oldPassword, '')
})
