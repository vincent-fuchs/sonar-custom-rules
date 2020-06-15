
class A {
    void foo() {

        try{
            throw new Exception("some exception");
        }
        catch(Exception e){
            log.error("some exception !"); // Noncompliant

            System.out.println("some logging");

            log.error("some exception ! "+e); // Noncompliant

            log.error("some exception ! ",e);

            log.info("some exception at info level! "); // ok, because at info level
        }

        try{
            throw new CustomException("some custom exception");
        }
        catch(CustomException e){ // not a generic Exception, so it's OK
            log.error("some exception !");

            log.error("some exception ! "+e);
        }
    }
}
