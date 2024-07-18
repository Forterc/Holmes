// If enabled, config will be injected here. Accessible via var config (dictionary)
if (!Java.available) log('Java unavailable, script will fail.');
Java.perform(function(){
function log(msg, lvl='info'){
    send('{"msg": ' + JSON.stringify(msg) + ', "loglvl":' + lvl + '}');
}
log('Injected')

// Logic goes here.
function main(){
    log('Starting main flow:')
    try{
        // Sample logic, replace this with your use case.
        // Debugging view constructors
        let view = Java.use("android.view.View");
        view.$init.overloads.forEach(
            function(overload){
                overload.implementation = function(){
                    log('Stack Trace: ' + _getStackTrace())
                    log('Args array: ' + arguments)
                    overload.apply(this, arguments)
                }
            }
        )
    }
    catch(error){
        log('Error in main: '+error)
    }
}

// _basic_ debugging utilities.
// Using threads instead of Exception to maintain flow integrity
function _getStackTrace() {
    var thread = Java.use('java.lang.Thread')
    var stack = thread.currentThread().getStackTrace()
    var traceString = "STACK_TRACE - \\n"
    // trimming the first two lines, since they will always be this functions thread call stack artifact.
    for (var i = 2; i < stack.length; i++) {
        traceString += stack[i] + "\\n";
    }
    return traceString;
}

// Describe class structure.
// Roughly based on: https://github.com/frida/frida-java-bridge/issues/44
function describeJavaClass(className) {
    var jClass = Java.use(className);
    console.log(JSON.stringify({
      _name: className,
      _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(m => {
        return m
      }),
      _fields: jClass.class.getFields().map(f => {
        return f.toString()
      }) 
    }, null, 2));
  }

function _trackActivities() {
    var activityClass = Java.use('android.app.Activity')
    activityClass.onStart.implementation = function () {
        var activityName = this.getClass().getName();
        log('Starting activity: ' + activityName)
        this.onStart();
    }
    activityClass.onStop.implementation = function () {
        var activityName = this.getClass().getName();
        log('Stopping activity: ' + activityName)
        this.onStop();
    }
}

main();
})