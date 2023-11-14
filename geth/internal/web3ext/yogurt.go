package web3ext

const YogurtJs = `
web3._extend({
	property: 'yogurt',
	methods: [
		new web3._extend.Method({
			name: 'getSnapshot',
			call: 'yogurt_getSnapshot',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputBlockNumberFormatter]
		}),
		new web3._extend.Method({
			name: 'getSnapshotAtHash',
			call: 'yogurt_getSnapshotAtHash',
			params: 1
		}),
		new web3._extend.Method({
			name: 'getSigners',
			call: 'yogurt_getSigners',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputBlockNumberFormatter]
		}),
		new web3._extend.Method({
			name: 'getSignersAtHash',
			call: 'yogurt_getSignersAtHash',
			params: 1
		}),
		new web3._extend.Method({
			name: 'propose',
			call: 'yogurt_propose',
			params: 2
		}),
		new web3._extend.Method({
			name: 'discard',
			call: 'yogurt_discard',
			params: 1
		}),
		new web3._extend.Method({
			name: 'status',
			call: 'yogurt_status',
			params: 0
		}),
		new web3._extend.Method({
			name: 'getSigner',
			call: 'yogurt_getSigner',
			params: 1,
			inputFormatter: [null]
		}),
	],
	properties: [
		new web3._extend.Property({
			name: 'proposals',
			getter: 'yogurt_proposals'
		}),
	]
});
`
