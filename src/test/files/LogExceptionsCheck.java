
class A {
    void foo() {

        try{
            throw new Exception("some exception")
        }
        catch(Exception e){
            log.error("some exception !") // Noncompliant

            log.error("some exception ! "+e) // Noncompliant

            log.error("some exception ! ",e) // Compliant
        }
    }
}
