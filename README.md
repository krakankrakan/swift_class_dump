# Swift Class Dump
Dumps Classes from Swift binaries (similar to classdump for Obj-C). This might be useful for reverse-engineering Swift applications. Note that this is still a work-in-progress, so not all things might work as intended.

## Building
Build via `build.sh`.

## Example
An example output of `swift_class_dump`:
```
$> ARCH=ARM ./dump_swift_classes Browser

Class
	Name: ViewController
	FieldDescriptor:   0x29bc
	Fields:
		FieldName: 		webView
		MangledTypeName: 	So9WKWebViewCSgXw

		FieldName: 		progressBar
		MangledTypeName: 	So14UIProgressViewCSgXw

		FieldName: 		barView
		MangledTypeName: 	So6UIViewCSgXw

		FieldName: 		urlField
		MangledTypeName: 	So11UITextFieldCSgXw

		FieldName: 		backButton
		MangledTypeName: 	So15UIBarButtonItemCSgXw

		FieldName: 		forwardButton
		MangledTypeName: 	So15UIBarButtonItemCSgXw

		FieldName: 		reloadButton
		MangledTypeName: 	So15UIBarButtonItemCSgXw

		FieldName: 		urlStr
		MangledTypeName: 	SS

	Methods:
		Name: _$s7Browser14ViewControllerC03webB0So05WKWebB0CSgvg
		Demangled name: ViewController.webView.getter
		Virtual address: 0x100002688
		Flags: 0x12	Getter | Instance
		Impl:  0x2688

		Name: _$s7Browser14ViewControllerC03webB0So05WKWebB0CSgvs
		Demangled name: ViewController.webView.setter
		Virtual address: 0x100002738
		Flags: 0x13	Setter | Instance
		Impl:  0x2738

		Name: _$s7Browser14ViewControllerC03webB0So05WKWebB0CSgvM
		Demangled name: ViewController.webView.modify
		Virtual address: 0x1000028a0
		Flags: 0x14	ModifyCoroutine | Instance
		Impl:  0x28a0

		Name: _$s7Browser14ViewControllerC11progressBarSo010UIProgressB0CSgvg
		Demangled name: ViewController.progressBar.getter
		Virtual address: 0x100002a4c
		Flags: 0x12	Getter | Instance
		Impl:  0x2a4c
    ...
```